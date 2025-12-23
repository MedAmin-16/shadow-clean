import type { Request, Response } from "express";
import { storage } from "../../storage";
import { insertProjectSchema } from "@shared/schema";

export async function getAllProjects(req: Request, res: Response) {
  try {
    const projects = await storage.getAllProjects();
    res.json(projects);
  } catch (error) {
    console.error("Error fetching projects:", error);
    res.status(500).json({ error: "Failed to fetch projects" });
  }
}

export async function getProject(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const project = await storage.getProject(id);
    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }
    res.json(project);
  } catch (error) {
    console.error("Error fetching project:", error);
    res.status(500).json({ error: "Failed to fetch project" });
  }
}

export async function createProject(req: Request, res: Response) {
  try {
    const parsed = insertProjectSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }
    
    const project = await storage.createProject(parsed.data);
    res.status(201).json(project);
  } catch (error) {
    console.error("Error creating project:", error);
    res.status(500).json({ error: "Failed to create project" });
  }
}

export async function deleteProject(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const deleted = await storage.deleteProject(id);
    if (!deleted) {
      return res.status(404).json({ error: "Project not found" });
    }
    res.status(204).send();
  } catch (error) {
    console.error("Error deleting project:", error);
    res.status(500).json({ error: "Failed to delete project" });
  }
}
