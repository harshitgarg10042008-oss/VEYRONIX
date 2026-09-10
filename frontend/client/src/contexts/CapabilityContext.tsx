/**
 * CapabilityContext.tsx
 * Fetches GET /api/capabilities on mount and makes the authoritative manifest
 * available throughout the app.  The frontend must NEVER hardcode vendor counts,
 * control counts, framework IDs, or feature flags — it must consume this context.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

export interface VendorCapability {
  vendor_id: string;
  display_name: string;
  parser_version: string;
  supported_platforms: string[];
  supported_syntax_forms: string[];
  unsupported_syntax: string[];
  control_ids: string[];
  confidence_behavior: string;
  notes: string;
}

export interface CapabilityManifest {
  app_version: string;
  schema_version: string;
  control_pack_version: string;
  framework_pack_version: string;
  parser_registry_version: string;
  vendors: VendorCapability[];
  framework_ids: string[];
  max_upload_bytes: number;
  max_upload_mb: number;
  ai_available: boolean;
  ai_mode: "offline" | "external" | "disabled";
  persistence_mode: "memory" | "sqlite" | "postgresql";
  auth_mode: "local" | "token" | "oidc";
  total_control_count: number;
  vendor_count: number;
  features: Record<string, boolean>;
}

interface CapabilityContextValue {
  manifest: CapabilityManifest | null;
  loading: boolean;
  error: string | null;
  apiOnline: boolean;
  refresh: () => void;
}

const CapabilityContext = createContext<CapabilityContextValue>({
  manifest: null,
  loading: true,
  error: null,
  apiOnline: false,
  refresh: () => {},
});

export function CapabilityProvider({ children }: { children: ReactNode }) {
  const [manifest, setManifest] = useState<CapabilityManifest | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [rev, setRev] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    fetch(`${API_BASE}/api/capabilities`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<CapabilityManifest>;
      })
      .then((data) => {
        if (cancelled) return;
        setManifest(data);
        setApiOnline(true);
        setLoading(false);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(String(err));
        setApiOnline(false);
        setLoading(false);
      });

    return () => { cancelled = true; };
  }, [rev]);

  const refresh = () => setRev((r) => r + 1);

  return (
    <CapabilityContext.Provider value={{ manifest, loading, error, apiOnline, refresh }}>
      {children}
    </CapabilityContext.Provider>
  );
}

export function useCapabilities() {
  return useContext(CapabilityContext);
}
