CREATE TABLE "admin_sessions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar(255) NOT NULL,
	"session_token" varchar(255) NOT NULL,
	"ip_address" varchar(45),
	"user_agent" text,
	"is_active" boolean DEFAULT true,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"last_activity_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "admin_sessions_session_token_unique" UNIQUE("session_token")
);
--> statement-breakpoint
CREATE TABLE "assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"asset_name" varchar(255) NOT NULL,
	"asset_type" varchar(50) NOT NULL,
	"ip_address" varchar(45),
	"hostname" varchar(255),
	"status" varchar(20) DEFAULT 'active',
	"last_scanned_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar,
	"action" varchar(100) NOT NULL,
	"resource_type" varchar(50),
	"resource_id" varchar(255),
	"details" jsonb,
	"ip_address" varchar(45),
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cloud_scan_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"config_name" varchar(255) NOT NULL,
	"cloud_provider" varchar(50) NOT NULL,
	"account_id" varchar(100),
	"credentials" text,
	"regions" jsonb,
	"is_active" boolean DEFAULT true,
	"last_scan_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "compliance_reports" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"scan_id" varchar,
	"report_type" varchar(50) NOT NULL,
	"compliance_standard" varchar(100) NOT NULL,
	"status" varchar(20) DEFAULT 'pending',
	"score" numeric(5, 2),
	"findings" jsonb,
	"recommendations" jsonb,
	"file_url" text,
	"generated_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "credit_transactions" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" varchar NOT NULL,
	"transaction_type" varchar(50) NOT NULL,
	"amount" integer NOT NULL,
	"balance_before" integer NOT NULL,
	"balance_after" integer NOT NULL,
	"description" text,
	"metadata" jsonb,
	"agent_type" varchar(20),
	"scan_id" varchar,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "monitoring_schedules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"target" text NOT NULL,
	"frequency" varchar(20) NOT NULL,
	"next_scan_at" timestamp,
	"last_scan_at" timestamp,
	"is_active" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "phishing_campaigns" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"campaign_name" varchar(255) NOT NULL,
	"description" text,
	"template_id" varchar(100),
	"status" varchar(20) DEFAULT 'draft',
	"target_emails" jsonb,
	"launched_at" timestamp,
	"completed_at" timestamp,
	"click_rate" numeric(5, 2),
	"reporting_url" text,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "remediation_tracking" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vulnerability_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"status" varchar(20) DEFAULT 'pending',
	"assigned_to" varchar(255),
	"due_date" timestamp,
	"completed_at" timestamp,
	"verification_scan_id" varchar,
	"notes" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_reports" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"report_type" varchar(50) NOT NULL,
	"summary" text,
	"vulnerability_count" integer DEFAULT 0,
	"security_score" integer,
	"export_url" text,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_sandboxes" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"sandbox_type" varchar(50) NOT NULL,
	"sandbox_url" text,
	"is_active" boolean DEFAULT true,
	"isolation_level" varchar(20) DEFAULT 'full',
	"created_at" timestamp DEFAULT now() NOT NULL,
	"destroyed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "scans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"target" text NOT NULL,
	"user_id" varchar NOT NULL,
	"status" varchar(20) DEFAULT 'pending' NOT NULL,
	"current_agent" varchar(50),
	"progress" integer DEFAULT 0 NOT NULL,
	"started_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp,
	"error" text,
	"scan_type" varchar(50) DEFAULT 'standard',
	"agent_results" jsonb
);
--> statement-breakpoint
CREATE TABLE "shadowlogic_discoveries" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"shadowlogic_scan_id" varchar NOT NULL,
	"vulnerability_id" varchar,
	"discovery_type" varchar(50) NOT NULL,
	"details" jsonb NOT NULL,
	"evidence" text,
	"confidence" integer DEFAULT 0,
	"discovered_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "shadowlogic_scans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"target" text NOT NULL,
	"analysis_type" varchar(50) NOT NULL,
	"status" varchar(20) DEFAULT 'pending',
	"finding_count" integer DEFAULT 0,
	"started_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp,
	"metadata" jsonb
);
--> statement-breakpoint
CREATE TABLE "shadowlogic_vulnerabilities" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"shadowlogic_scan_id" varchar,
	"title" varchar(255) NOT NULL,
	"description" text NOT NULL,
	"severity" varchar(20) NOT NULL,
	"confidence" integer DEFAULT 0,
	"business_impact" text,
	"proof" text,
	"remediation" text,
	"detected_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "threat_intel" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"threat_type" varchar(50) NOT NULL,
	"threat_name" varchar(255) NOT NULL,
	"severity" varchar(20) NOT NULL,
	"cve_id" varchar(50),
	"description" text,
	"indicators" jsonb,
	"affected_systems" jsonb,
	"remediation_steps" jsonb,
	"source" varchar(100),
	"discovered_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_credits" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" varchar NOT NULL,
	"balance" integer DEFAULT 1000 NOT NULL,
	"plan_level" varchar(20) DEFAULT 'STANDARD' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "user_credits_user_id_unique" UNIQUE("user_id")
);
--> statement-breakpoint
CREATE TABLE "user_integrations" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" varchar NOT NULL,
	"integration_type" varchar(50) NOT NULL,
	"integration_name" varchar(100) NOT NULL,
	"api_key" text,
	"webhook_url" text,
	"is_active" boolean DEFAULT true,
	"config" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar(255) NOT NULL,
	"username" varchar(100) NOT NULL,
	"password_hash" varchar(255) NOT NULL,
	"full_name" varchar(255),
	"avatar_url" text,
	"plan" varchar(50) DEFAULT 'STANDARD',
	"status" varchar(50) DEFAULT 'active',
	"email_verified" boolean DEFAULT false,
	"two_factor_enabled" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"last_login" timestamp,
	CONSTRAINT "users_email_unique" UNIQUE("email"),
	CONSTRAINT "users_username_unique" UNIQUE("username")
);
--> statement-breakpoint
CREATE TABLE "vulnerabilities" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"title" varchar(255) NOT NULL,
	"severity" varchar(20) NOT NULL,
	"category" varchar(100),
	"cve_id" varchar(50),
	"description" text,
	"proof" text,
	"remediation" text,
	"affected_component" varchar(255),
	"discovered_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "admin_sessions_email_idx" ON "admin_sessions" USING btree ("email");--> statement-breakpoint
CREATE INDEX "admin_sessions_token_idx" ON "admin_sessions" USING btree ("session_token");--> statement-breakpoint
CREATE INDEX "assets_user_id_idx" ON "assets" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "audit_logs_user_id_idx" ON "audit_logs" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "audit_logs_action_idx" ON "audit_logs" USING btree ("action");--> statement-breakpoint
CREATE INDEX "cloud_scan_configs_user_id_idx" ON "cloud_scan_configs" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "compliance_reports_user_id_idx" ON "compliance_reports" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "compliance_reports_standard_idx" ON "compliance_reports" USING btree ("compliance_standard");--> statement-breakpoint
CREATE INDEX "credit_transactions_user_id_idx" ON "credit_transactions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "monitoring_schedules_user_id_idx" ON "monitoring_schedules" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "monitoring_schedules_is_active_idx" ON "monitoring_schedules" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "phishing_campaigns_user_id_idx" ON "phishing_campaigns" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "remediation_tracking_user_id_idx" ON "remediation_tracking" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "remediation_tracking_status_idx" ON "remediation_tracking" USING btree ("status");--> statement-breakpoint
CREATE INDEX "scan_reports_scan_id_idx" ON "scan_reports" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "scan_reports_user_id_idx" ON "scan_reports" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "scan_sandboxes_scan_id_idx" ON "scan_sandboxes" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "scan_sandboxes_user_id_idx" ON "scan_sandboxes" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "scans_user_id_idx" ON "scans" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "scans_status_idx" ON "scans" USING btree ("status");--> statement-breakpoint
CREATE INDEX "shadowlogic_discoveries_shadowlogic_scan_id_idx" ON "shadowlogic_discoveries" USING btree ("shadowlogic_scan_id");--> statement-breakpoint
CREATE INDEX "shadowlogic_scans_scan_id_idx" ON "shadowlogic_scans" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "shadowlogic_scans_user_id_idx" ON "shadowlogic_scans" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "shadowlogic_vulnerabilities_scan_id_idx" ON "shadowlogic_vulnerabilities" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "shadowlogic_vulnerabilities_user_id_idx" ON "shadowlogic_vulnerabilities" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "threat_intel_cve_id_idx" ON "threat_intel" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "threat_intel_threat_type_idx" ON "threat_intel" USING btree ("threat_type");--> statement-breakpoint
CREATE INDEX "user_credits_user_id_idx" ON "user_credits" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "user_integrations_user_id_idx" ON "user_integrations" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "users_email_idx" ON "users" USING btree ("email");--> statement-breakpoint
CREATE INDEX "vulnerabilities_scan_id_idx" ON "vulnerabilities" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "vulnerabilities_user_id_idx" ON "vulnerabilities" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "vulnerabilities_cve_id_idx" ON "vulnerabilities" USING btree ("cve_id");