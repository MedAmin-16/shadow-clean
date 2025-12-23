import { db, pool } from "../../db";
import { 
  userCreditsTable, 
  creditTransactionsTable, 
  type PlanLevel, 
  type CreditTransactionType,
  type UserCredits 
} from "@shared/schema";
import { eq, desc } from "drizzle-orm";

export interface CreditDeductionResult {
  success: boolean;
  newBalance: number;
  transactionId?: number;
  error?: string;
}

export interface CreditTransactionInput {
  userId: string;
  transactionType: CreditTransactionType;
  amount: number;
  description?: string;
  metadata?: Record<string, unknown>;
  agentType?: string;
  scanId?: string;
}

class CreditService {
  async getUserCredits(userId: string): Promise<UserCredits> {
    const result = await db
      .select()
      .from(userCreditsTable)
      .where(eq(userCreditsTable.userId, userId))
      .limit(1);

    if (result.length === 0) {
      const newCredits = await this.initializeUserCredits(userId);
      return {
        userId: newCredits.user_id,
        balance: newCredits.balance,
        planLevel: newCredits.plan_level as PlanLevel,
        lastUpdated: newCredits.updated_at ? new Date(newCredits.updated_at).toISOString() : new Date().toISOString(),
      };
    }

    return {
      userId: result[0].userId,
      balance: result[0].balance,
      planLevel: result[0].planLevel as PlanLevel,
      lastUpdated: result[0].updatedAt ? result[0].updatedAt.toISOString() : new Date().toISOString(),
    };
  }

  private async initializeUserCredits(userId: string, initialBalance = 1000, planLevel: PlanLevel = "STANDARD") {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const insertResult = await client.query(
        `INSERT INTO user_credits (user_id, balance, plan_level, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (user_id) DO NOTHING
         RETURNING *`,
        [userId, initialBalance, planLevel]
      );

      if (insertResult.rows.length > 0) {
        await client.query(
          `INSERT INTO credit_transactions 
           (user_id, transaction_type, amount, balance_before, balance_after, description, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
          [userId, "initial_grant", initialBalance, 0, initialBalance, "Initial credit grant for new user"]
        );
      }

      await client.query("COMMIT");

      if (insertResult.rows.length > 0) {
        return insertResult.rows[0];
      }

      const existing = await client.query(
        "SELECT * FROM user_credits WHERE user_id = $1",
        [userId]
      );
      return existing.rows[0];
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async deductCredits(
    userId: string,
    amount: number,
    options: {
      description?: string;
      agentType?: string;
      scanId?: string;
      metadata?: Record<string, unknown>;
    } = {}
  ): Promise<CreditDeductionResult> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const lockResult = await client.query(
        "SELECT * FROM user_credits WHERE user_id = $1 FOR UPDATE",
        [userId]
      );

      if (lockResult.rows.length === 0) {
        await this.initializeUserCredits(userId);
        const retryResult = await client.query(
          "SELECT * FROM user_credits WHERE user_id = $1 FOR UPDATE",
          [userId]
        );
        if (retryResult.rows.length === 0) {
          await client.query("ROLLBACK");
          return { success: false, newBalance: 0, error: "Failed to initialize user credits" };
        }
        lockResult.rows = retryResult.rows;
      }

      const currentBalance = lockResult.rows[0].balance;

      if (currentBalance < amount) {
        await client.query("ROLLBACK");
        return {
          success: false,
          newBalance: currentBalance,
          error: `Insufficient credits. Required: ${amount}, Available: ${currentBalance}`,
        };
      }

      const newBalance = currentBalance - amount;

      await client.query(
        `UPDATE user_credits 
         SET balance = $1, updated_at = NOW() 
         WHERE user_id = $2`,
        [newBalance, userId]
      );

      const transactionResult = await client.query(
        `INSERT INTO credit_transactions 
         (user_id, transaction_type, amount, balance_before, balance_after, description, metadata, agent_type, scan_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
         RETURNING id`,
        [
          userId,
          options.agentType ? "agent_deduction" : "scan_deduction",
          -amount,
          currentBalance,
          newBalance,
          options.description || `Credit deduction of ${amount}`,
          options.metadata ? JSON.stringify(options.metadata) : null,
          options.agentType || null,
          options.scanId || null,
        ]
      );

      await client.query("COMMIT");

      return {
        success: true,
        newBalance,
        transactionId: transactionResult.rows[0].id,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("[CreditService] Deduction error:", error);
      return {
        success: false,
        newBalance: 0,
        error: error instanceof Error ? error.message : "Unknown error during credit deduction",
      };
    } finally {
      client.release();
    }
  }

  async addCredits(
    userId: string,
    amount: number,
    transactionType: CreditTransactionType = "purchase",
    options: {
      description?: string;
      metadata?: Record<string, unknown>;
    } = {}
  ): Promise<UserCredits> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      let lockResult = await client.query(
        "SELECT * FROM user_credits WHERE user_id = $1 FOR UPDATE",
        [userId]
      );

      if (lockResult.rows.length === 0) {
        await this.initializeUserCredits(userId);
        lockResult = await client.query(
          "SELECT * FROM user_credits WHERE user_id = $1 FOR UPDATE",
          [userId]
        );
      }

      const currentBalance = lockResult.rows[0].balance;
      const newBalance = currentBalance + amount;

      await client.query(
        `UPDATE user_credits 
         SET balance = $1, updated_at = NOW() 
         WHERE user_id = $2`,
        [newBalance, userId]
      );

      await client.query(
        `INSERT INTO credit_transactions 
         (user_id, transaction_type, amount, balance_before, balance_after, description, metadata, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
        [
          userId,
          transactionType,
          amount,
          currentBalance,
          newBalance,
          options.description || `Credit addition of ${amount}`,
          options.metadata ? JSON.stringify(options.metadata) : null,
        ]
      );

      await client.query("COMMIT");

      return {
        userId,
        balance: newBalance,
        planLevel: lockResult.rows[0].plan_level as PlanLevel,
        lastUpdated: new Date().toISOString(),
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async refundCredits(
    userId: string,
    amount: number,
    reason: string,
    originalTransactionId?: number
  ): Promise<UserCredits> {
    return this.addCredits(userId, amount, "refund", {
      description: `Refund: ${reason}`,
      metadata: originalTransactionId ? { originalTransactionId } : undefined,
    });
  }

  async setUserPlanLevel(userId: string, planLevel: PlanLevel): Promise<UserCredits> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      let lockResult = await client.query(
        "SELECT * FROM user_credits WHERE user_id = $1 FOR UPDATE",
        [userId]
      );

      if (lockResult.rows.length === 0) {
        await this.initializeUserCredits(userId, 1000, planLevel);
        lockResult = await client.query(
          "SELECT * FROM user_credits WHERE user_id = $1 FOR UPDATE",
          [userId]
        );
      }

      const oldPlanLevel = lockResult.rows[0].plan_level;

      await client.query(
        `UPDATE user_credits 
         SET plan_level = $1, updated_at = NOW() 
         WHERE user_id = $2`,
        [planLevel, userId]
      );

      await client.query(
        `INSERT INTO credit_transactions 
         (user_id, transaction_type, amount, balance_before, balance_after, description, metadata, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
        [
          userId,
          "plan_upgrade",
          0,
          lockResult.rows[0].balance,
          lockResult.rows[0].balance,
          `Plan level changed from ${oldPlanLevel} to ${planLevel}`,
          JSON.stringify({ oldPlanLevel, newPlanLevel: planLevel }),
        ]
      );

      await client.query("COMMIT");

      return {
        userId,
        balance: lockResult.rows[0].balance,
        planLevel,
        lastUpdated: new Date().toISOString(),
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async getTransactionHistory(
    userId: string,
    limit = 50,
    offset = 0
  ): Promise<{
    transactions: Array<{
      id: number;
      transactionType: string;
      amount: number;
      balanceBefore: number;
      balanceAfter: number;
      description: string | null;
      agentType: string | null;
      scanId: string | null;
      createdAt: Date;
    }>;
    total: number;
  }> {
    const transactions = await db
      .select()
      .from(creditTransactionsTable)
      .where(eq(creditTransactionsTable.userId, userId))
      .orderBy(desc(creditTransactionsTable.createdAt))
      .limit(limit)
      .offset(offset);

    const countResult = await db
      .select()
      .from(creditTransactionsTable)
      .where(eq(creditTransactionsTable.userId, userId));

    return {
      transactions: transactions.map((t) => ({
        id: t.id,
        transactionType: t.transactionType,
        amount: t.amount,
        balanceBefore: t.balanceBefore,
        balanceAfter: t.balanceAfter,
        description: t.description,
        agentType: t.agentType,
        scanId: t.scanId,
        createdAt: t.createdAt,
      })),
      total: countResult.length,
    };
  }

  async checkSufficientCredits(userId: string, requiredAmount: number): Promise<{
    sufficient: boolean;
    currentBalance: number;
    shortfall: number;
  }> {
    const credits = await this.getUserCredits(userId);
    const shortfall = Math.max(0, requiredAmount - credits.balance);
    return {
      sufficient: credits.balance >= requiredAmount,
      currentBalance: credits.balance,
      shortfall,
    };
  }

  async reserveCredits(
    userId: string,
    amount: number,
    scanId: string,
    description: string
  ): Promise<CreditDeductionResult> {
    return this.deductCredits(userId, amount, {
      description: `Reserved: ${description}`,
      scanId,
      metadata: { reserved: true, scanId },
    });
  }
}

export const creditService = new CreditService();
