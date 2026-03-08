import { bridgeRequest, BridgeResponse } from "./bridge-client";

export interface DomainOsintResult {
  domain: string;
  registered: boolean;
  ip_addresses: Array<{
    ip: string;
    geo: {
      country: string;
      city: string;
      lat: number;
      lon: number;
      isp: string;
      asn: string;
    };
  }>;
  dns_records: Array<{
    type: string;
    value: string;
  }>;
  whois: {
    registrar: string;
    creation_date: string;
    expiration_date: string;
    name_servers: string[];
    registrant?: string;
  };
  certificates: Array<{
    issuer: string;
    subject: string;
    not_before: string;
    not_after: string;
    san: string[];
  }>;
  subdomains: string[];
  reverse_ip_domains: string[];
  reputation?: {
    score: number;
    categories: string[];
  };
}

export interface IpOsintResult {
  ip: string;
  type: string;
  country: string;
  country_code: string;
  city: string;
  region: string;
  latitude: number;
  longitude: number;
  isp: string;
  org: string;
  asn: string;
  timezone: string;
  postal: string;
  map_url: string;
}

export interface PhoneOsintResult {
  phone: string;
  valid: boolean;
  country: string;
  carrier: string;
  line_type: string;
  timezone: string;
  region: string;
}

export async function domainRecon(
  domain: string
): Promise<BridgeResponse<DomainOsintResult>> {
  return bridgeRequest<DomainOsintResult>("/osint/domain", { domain });
}

export async function ipLookup(
  ip: string
): Promise<BridgeResponse<IpOsintResult>> {
  return bridgeRequest<IpOsintResult>("/osint/ip", { ip });
}

export async function phoneLookup(
  phone: string
): Promise<BridgeResponse<PhoneOsintResult>> {
  return bridgeRequest<PhoneOsintResult>("/osint/phone", { phone });
}
