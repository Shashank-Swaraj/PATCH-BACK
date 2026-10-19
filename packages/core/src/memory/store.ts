import fs from 'node:fs';
import path from 'node:path';
import { SecurityInvariant, SecurityInvariantSchema } from '../types/invariant.js';
import { AdvisoryRecord } from '../types/advisory.js';

export interface MemoryStoreData {
  version: string;
  advisories: Record<string, AdvisoryRecord>;
  invariants: Record<string, SecurityInvariant>;
}

export class PatchMemoryStore {
  private filePath?: string;
  private advisories: Map<string, AdvisoryRecord> = new Map();
  private invariants: Map<string, SecurityInvariant> = new Map();

  constructor(filePath?: string) {
    this.filePath = filePath;
    if (filePath && fs.existsSync(filePath)) {
      this.loadFromFile(filePath);
    }
  }

  public addAdvisory(advisory: AdvisoryRecord): void {
    this.advisories.set(advisory.id, advisory);
    this.persist();
  }

  public getAdvisory(id: string): AdvisoryRecord | undefined {
    return this.advisories.get(id);
  }

  public addInvariant(invariant: SecurityInvariant): void {
    SecurityInvariantSchema.parse(invariant);
    this.invariants.set(invariant.id, invariant);
    this.persist();
  }

  public getInvariant(id: string): SecurityInvariant | undefined {
    return this.invariants.get(id);
  }

  public getInvariantsForPackage(packageName: string): SecurityInvariant[] {
    return Array.from(this.invariants.values()).filter(
      (inv) => inv.packageName === packageName && inv.enabled
    );
  }

  public getAllInvariants(): SecurityInvariant[] {
    return Array.from(this.invariants.values());
  }

  public getAllAdvisories(): AdvisoryRecord[] {
    return Array.from(this.advisories.values());
  }

  private persist(): void {
    if (!this.filePath) return;
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const data: MemoryStoreData = {
      version: '1.0.0',
      advisories: Object.fromEntries(this.advisories),
      invariants: Object.fromEntries(this.invariants),
    };

    fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  private loadFromFile(filePath: string): void {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const data = JSON.parse(raw) as MemoryStoreData;

    this.advisories = new Map(Object.entries(data.advisories || {}));
    this.invariants = new Map(Object.entries(data.invariants || {}));
  }
}
