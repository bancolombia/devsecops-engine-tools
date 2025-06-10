export class Finding {

    private id: string;
    private customVulnId: string;
    private checkName: string;
    private checkClass: string;
    private severity: string;
    private where: string;
    private resource: string;
    private description: string;
    private module: string;
    private tool: string;
    private vulnerabilityStatus?: string;
    private targetImage?: string;
    private installedVersion?: string;
    private fixedVersion?: string;
    private packageName?: string;
    private cvssScore?: string;
    private references: string[];

    constructor(
        id: string,
        customVulnId: string,
        checkName: string,
        checkClass: string,
        severity: string,
        where: string,
        resource: string,
        description: string,
        module: string,
        tool: string,
        vulnerabilityStatus?: string,
        targetImage?: string,
        installedVersion?: string,
        fixedVersion?: string,
        packageName?: string,
        cvssScore?: string,
        references: string[] = []
    ) {
        this.id = id;
        this.customVulnId = customVulnId;
        this.checkName = checkName;
        this.checkClass = checkClass;
        this.severity = severity;
        this.where = where;
        this.resource = resource;
        this.description = description;
        this.module = module;
        this.tool = tool;
        this.vulnerabilityStatus = vulnerabilityStatus;
        this.targetImage = targetImage;
        this.installedVersion = installedVersion;
        this.fixedVersion = fixedVersion;
        this.packageName = packageName;
        this.cvssScore = cvssScore;
        this.references = references;
    }

    public getId(): string {
        return this.id;
    }

    public getCustomVulnId(): string {
        return this.customVulnId;
    }

    public getCheckName(): string {
        return this.checkName;
    }

    public getCheckClass(): string {
        return this.checkClass;
    }

    public getSeverity(): string {
        return this.severity;
    }

    public getWhere(): string {
        return this.where;
    }

    public getResource(): string {
        return this.resource;
    }

    public getDescription(): string {
        return this.description;
    }

    public getModule(): string {
        return this.module;
    }

    public getTool(): string {
        return this.tool;
    }

    public getVulnerabilityStatus(): string | undefined {
        return this.vulnerabilityStatus;
    }
    public getTargetImage(): string | undefined {
        return this.targetImage;
    }

    public getInstalledVersion(): string | undefined {
        return this.installedVersion;
    }

    public getFixedVersion(): string | undefined {
        return this.fixedVersion;
    }

    public getPackageName(): string | undefined {
        return this.packageName;
    }

    public getCvssScore(): string | undefined {
        return this.cvssScore;
    }

    public getReferences(): string[] {
        return this.references;
    }

}