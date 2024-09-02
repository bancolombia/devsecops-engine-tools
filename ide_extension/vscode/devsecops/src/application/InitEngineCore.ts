import { IacScanner } from "../infraestructure/drivenAdapter/IacScanner";
import { IacScanRequest } from "../infraestructure/entryPoint/IacScanRequest";
import { IacScanUseCase } from "../domain/usecase/IacScanUseCase";

export function iacScanRequest(): IacScanRequest {
    const iacScanner = new IacScanner();
    const iacScanUseCase = new IacScanUseCase(new IacScanner());
    return new IacScanRequest(iacScanUseCase);
}