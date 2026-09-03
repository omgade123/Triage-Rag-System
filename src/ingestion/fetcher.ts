import { config } from "../config";

interface NvdCveItem {
  cve: {
    id: string;
    descriptions: Array<{ lang: string; value: string }>;
    weaknesses?: Array<{
      description: Array<{ lang: string; value: string }>;
    }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: {
          baseScore: number;
          baseSeverity: string;
        };
      }>;
      cvssMetricV2?: Array<{
        cvssData: {
          baseScore: number;
        };
        baseSeverity?: string;
      }>;
    };
    published?: string;
  };
}

interface NvdApiResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: NvdCveItem[];
}

export interface FetchedReport {
  id: string;
  title: string;
  description: string;
  cwe: string | null;
  severity: string | null;
  cvssScore: number | null;
  publishedAt: string | null;
}

const NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/**
 * Fetches a page of CVE records from the NVD API.
 * Respects rate limits: 5 req/30s without key, 50 req/30s with key.
 */
export async function fetchCvePage(
  startIndex: number = 0,
  resultsPerPage: number = 50
): Promise<{ reports: FetchedReport[]; totalResults: number }> {
  const url = new URL(NVD_BASE_URL);
  url.searchParams.set("startIndex", String(startIndex));
  url.searchParams.set("resultsPerPage", String(resultsPerPage));

  const headers: Record<string, string> = {};
  if (config.nvdApiKey) {
    headers["apiKey"] = config.nvdApiKey;
  }

  const response = await fetch(url.toString(), { headers });

  if (!response.ok) {
    throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as NvdApiResponse;

  const reports: FetchedReport[] = data.vulnerabilities.map((item) => {
    const cve = item.cve;

    // Get English description
    const descEntry = cve.descriptions.find((d) => d.lang === "en");
    const description = descEntry?.value || "";

    // Extract CWE
    const cweEntry = cve.weaknesses?.[0]?.description?.find(
      (d) => d.lang === "en"
    );
    const cwe =
      cweEntry?.value && cweEntry.value !== "NVD-CWE-noinfo"
        ? cweEntry.value
        : null;

    // Extract CVSS score and severity (prefer v3.1)
    const cvssV3 = cve.metrics?.cvssMetricV31?.[0];
    const cvssV2 = cve.metrics?.cvssMetricV2?.[0];

    const cvssScore =
      cvssV3?.cvssData.baseScore ?? cvssV2?.cvssData.baseScore ?? null;
    const severity =
      cvssV3?.cvssData.baseSeverity ?? cvssV2?.baseSeverity ?? null;

    return {
      id: cve.id,
      title: cve.id, // NVD doesn't have a separate title; use the CVE ID
      description,
      cwe,
      severity: severity?.toUpperCase() ?? null,
      cvssScore,
      publishedAt: cve.published ?? null,
    };
  });

  return { reports, totalResults: data.totalResults };
}

/**
 * Delay helper for rate-limit compliance.
 */
export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
