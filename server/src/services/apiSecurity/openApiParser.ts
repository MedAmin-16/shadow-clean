import { z } from "zod";

export interface OpenApiEndpoint {
  path: string;
  method: string;
  operationId?: string;
  summary?: string;
  description?: string;
  parameters: OpenApiParameter[];
  requestBody?: OpenApiRequestBody;
  responses: Record<string, OpenApiResponse>;
  security?: OpenApiSecurityRequirement[];
  tags?: string[];
}

export interface OpenApiParameter {
  name: string;
  in: "query" | "header" | "path" | "cookie";
  required?: boolean;
  schema?: OpenApiSchema;
  description?: string;
}

export interface OpenApiRequestBody {
  required?: boolean;
  content: Record<string, { schema?: OpenApiSchema }>;
}

export interface OpenApiResponse {
  description: string;
  content?: Record<string, { schema?: OpenApiSchema }>;
}

export interface OpenApiSchema {
  type?: string;
  properties?: Record<string, OpenApiSchema>;
  items?: OpenApiSchema;
  required?: string[];
  format?: string;
  enum?: unknown[];
  $ref?: string;
  additionalProperties?: boolean | OpenApiSchema;
}

export interface OpenApiSecurityRequirement {
  [schemeName: string]: string[];
}

export interface OpenApiSecurityScheme {
  type: "apiKey" | "http" | "oauth2" | "openIdConnect";
  name?: string;
  in?: "query" | "header" | "cookie";
  scheme?: string;
  bearerFormat?: string;
  flows?: Record<string, unknown>;
  openIdConnectUrl?: string;
}

export interface ParsedOpenApiSpec {
  version: string;
  title: string;
  description?: string;
  servers: { url: string; description?: string }[];
  endpoints: OpenApiEndpoint[];
  securitySchemes: Record<string, OpenApiSecurityScheme>;
  schemas: Record<string, OpenApiSchema>;
  securityRequirements: OpenApiSecurityRequirement[];
}

export interface OpenApiParseResult {
  success: boolean;
  spec?: ParsedOpenApiSpec;
  errors?: string[];
  warnings?: string[];
}

class OpenApiParserService {
  parse(specContent: string): OpenApiParseResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      let rawSpec: Record<string, unknown>;
      
      try {
        rawSpec = JSON.parse(specContent);
      } catch {
        try {
          rawSpec = this.parseYaml(specContent);
        } catch {
          errors.push("Invalid specification format. Must be valid JSON or YAML.");
          return { success: false, errors };
        }
      }

      const version = this.detectVersion(rawSpec);
      if (!version) {
        errors.push("Could not detect OpenAPI/Swagger version.");
        return { success: false, errors };
      }

      const spec = this.parseSpec(rawSpec, version, warnings);
      
      return {
        success: true,
        spec,
        warnings: warnings.length > 0 ? warnings : undefined,
      };
    } catch (error) {
      errors.push(error instanceof Error ? error.message : "Unknown parsing error");
      return { success: false, errors };
    }
  }

  private parseYaml(content: string): Record<string, unknown> {
    const lines = content.split("\n");
    const result: Record<string, unknown> = {};
    const stack: { indent: number; obj: Record<string, unknown> }[] = [{ indent: -1, obj: result }];

    for (const line of lines) {
      if (line.trim() === "" || line.trim().startsWith("#")) continue;

      const indent = line.search(/\S/);
      const trimmed = line.trim();

      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
        stack.pop();
      }

      const colonIndex = trimmed.indexOf(":");
      if (colonIndex > 0) {
        const key = trimmed.substring(0, colonIndex).trim();
        let value: unknown = trimmed.substring(colonIndex + 1).trim();

        if (value === "") {
          const newObj: Record<string, unknown> = {};
          stack[stack.length - 1].obj[key] = newObj;
          stack.push({ indent, obj: newObj });
        } else {
          if (value === "true") value = true;
          else if (value === "false") value = false;
          else if (!isNaN(Number(value))) value = Number(value);
          else if (typeof value === "string" && value.startsWith('"') && value.endsWith('"')) {
            value = value.slice(1, -1);
          }
          stack[stack.length - 1].obj[key] = value;
        }
      }
    }

    return result;
  }

  private detectVersion(spec: Record<string, unknown>): string | null {
    if (spec.openapi && typeof spec.openapi === "string") {
      return spec.openapi;
    }
    if (spec.swagger && typeof spec.swagger === "string") {
      return spec.swagger;
    }
    return null;
  }

  private parseSpec(
    rawSpec: Record<string, unknown>,
    version: string,
    warnings: string[]
  ): ParsedOpenApiSpec {
    const info = (rawSpec.info as Record<string, unknown>) || {};
    const servers = this.parseServers(rawSpec, version);
    const endpoints = this.parseEndpoints(rawSpec, warnings);
    const securitySchemes = this.parseSecuritySchemes(rawSpec);
    const schemas = this.parseSchemas(rawSpec);
    const securityRequirements = this.parseSecurityRequirements(rawSpec);

    return {
      version,
      title: String(info.title || "Untitled API"),
      description: info.description ? String(info.description) : undefined,
      servers,
      endpoints,
      securitySchemes,
      schemas,
      securityRequirements,
    };
  }

  private parseServers(spec: Record<string, unknown>, version: string): { url: string; description?: string }[] {
    if (version.startsWith("3")) {
      const servers = spec.servers as { url: string; description?: string }[] || [];
      return servers.map(s => ({ url: s.url, description: s.description }));
    }
    const host = spec.host as string || "localhost";
    const basePath = spec.basePath as string || "";
    const schemes = spec.schemes as string[] || ["https"];
    return [{ url: `${schemes[0]}://${host}${basePath}` }];
  }

  private parseEndpoints(spec: Record<string, unknown>, warnings: string[]): OpenApiEndpoint[] {
    const endpoints: OpenApiEndpoint[] = [];
    const paths = (spec.paths as Record<string, Record<string, unknown>>) || {};

    for (const [path, pathItem] of Object.entries(paths)) {
      const methods = ["get", "post", "put", "patch", "delete", "options", "head"];
      
      for (const method of methods) {
        const operation = pathItem[method] as Record<string, unknown>;
        if (!operation) continue;

        const endpoint = this.parseOperation(path, method, operation, pathItem, warnings);
        endpoints.push(endpoint);
      }
    }

    return endpoints;
  }

  private parseOperation(
    path: string,
    method: string,
    operation: Record<string, unknown>,
    pathItem: Record<string, unknown>,
    warnings: string[]
  ): OpenApiEndpoint {
    const pathParameters = (pathItem.parameters as unknown[]) || [];
    const operationParameters = (operation.parameters as unknown[]) || [];
    const allParameters = [...pathParameters, ...operationParameters];

    const parameters = allParameters.map((p) => this.parseParameter(p as Record<string, unknown>));
    const requestBody = operation.requestBody ? this.parseRequestBody(operation.requestBody as Record<string, unknown>) : undefined;
    const responses = this.parseResponses((operation.responses as Record<string, unknown>) || {});
    const security = operation.security as OpenApiSecurityRequirement[] | undefined;

    if (!operation.operationId) {
      warnings.push(`Endpoint ${method.toUpperCase()} ${path} has no operationId`);
    }

    return {
      path,
      method: method.toUpperCase(),
      operationId: operation.operationId as string | undefined,
      summary: operation.summary as string | undefined,
      description: operation.description as string | undefined,
      parameters,
      requestBody,
      responses,
      security,
      tags: operation.tags as string[] | undefined,
    };
  }

  private parseParameter(param: Record<string, unknown>): OpenApiParameter {
    return {
      name: String(param.name || ""),
      in: (param.in as "query" | "header" | "path" | "cookie") || "query",
      required: Boolean(param.required),
      schema: param.schema as OpenApiSchema | undefined,
      description: param.description as string | undefined,
    };
  }

  private parseRequestBody(body: Record<string, unknown>): OpenApiRequestBody {
    return {
      required: Boolean(body.required),
      content: (body.content as Record<string, { schema?: OpenApiSchema }>) || {},
    };
  }

  private parseResponses(responses: Record<string, unknown>): Record<string, OpenApiResponse> {
    const parsed: Record<string, OpenApiResponse> = {};
    
    for (const [code, response] of Object.entries(responses)) {
      const r = response as Record<string, unknown>;
      parsed[code] = {
        description: String(r.description || ""),
        content: r.content as Record<string, { schema?: OpenApiSchema }> | undefined,
      };
    }

    return parsed;
  }

  private parseSecuritySchemes(spec: Record<string, unknown>): Record<string, OpenApiSecurityScheme> {
    const components = (spec.components as Record<string, unknown>) || {};
    const securityDefinitions = (spec.securityDefinitions as Record<string, unknown>) || {};
    const schemes = (components.securitySchemes as Record<string, unknown>) || securityDefinitions;

    const parsed: Record<string, OpenApiSecurityScheme> = {};
    
    for (const [name, scheme] of Object.entries(schemes)) {
      const s = scheme as Record<string, unknown>;
      parsed[name] = {
        type: s.type as OpenApiSecurityScheme["type"],
        name: s.name as string | undefined,
        in: s.in as "query" | "header" | "cookie" | undefined,
        scheme: s.scheme as string | undefined,
        bearerFormat: s.bearerFormat as string | undefined,
      };
    }

    return parsed;
  }

  private parseSchemas(spec: Record<string, unknown>): Record<string, OpenApiSchema> {
    const components = (spec.components as Record<string, unknown>) || {};
    const definitions = (spec.definitions as Record<string, OpenApiSchema>) || {};
    const schemas = (components.schemas as Record<string, OpenApiSchema>) || definitions;
    return schemas;
  }

  private parseSecurityRequirements(spec: Record<string, unknown>): OpenApiSecurityRequirement[] {
    return (spec.security as OpenApiSecurityRequirement[]) || [];
  }

  getResourceEndpoints(spec: ParsedOpenApiSpec): Map<string, OpenApiEndpoint[]> {
    const resourceMap = new Map<string, OpenApiEndpoint[]>();

    for (const endpoint of spec.endpoints) {
      const resourcePath = this.extractResourcePath(endpoint.path);
      
      if (!resourceMap.has(resourcePath)) {
        resourceMap.set(resourcePath, []);
      }
      resourceMap.get(resourcePath)!.push(endpoint);
    }

    return resourceMap;
  }

  private extractResourcePath(path: string): string {
    const segments = path.split("/").filter(Boolean);
    const resourceSegments: string[] = [];

    for (const segment of segments) {
      if (segment.startsWith("{") && segment.endsWith("}")) {
        break;
      }
      resourceSegments.push(segment);
    }

    return "/" + resourceSegments.join("/");
  }

  findEndpointsWithIdParams(spec: ParsedOpenApiSpec): OpenApiEndpoint[] {
    return spec.endpoints.filter((endpoint) => {
      const hasIdInPath = /\{[^}]*[Ii]d[^}]*\}/.test(endpoint.path) || 
                          endpoint.parameters.some(p => 
                            p.in === "path" && /[Ii]d$/.test(p.name)
                          );
      return hasIdInPath;
    });
  }

  findEndpointsAcceptingObjects(spec: ParsedOpenApiSpec): OpenApiEndpoint[] {
    return spec.endpoints.filter((endpoint) => {
      if (!endpoint.requestBody) return false;
      
      const jsonContent = endpoint.requestBody.content["application/json"];
      if (!jsonContent?.schema) return false;

      return jsonContent.schema.type === "object" || jsonContent.schema.properties;
    });
  }
}

export const openApiParser = new OpenApiParserService();
