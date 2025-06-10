import { Finding } from "./Finding";

export class ScannerRes {

    private status: boolean;
    private findings: Finding[];
    
    constructor(status:boolean, findings: Finding[]) {
        this.status = status;
        this.findings = findings;
    }

    public getStatus(): boolean {
        return this.status;
    }

    public getFindings(): Finding[] {
        return this.findings;
    }

}