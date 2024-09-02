import { IacScanner } from "../infraestructure/drivenAdapter/IacScanner";
import { IacScanRequest } from "../infraestructure/entryPoint/IacScanRequest";
import { IacScanUseCase } from "../domain/usecase/IacScanUseCase";
import { RestClient } from "../infraestructure/drivenAdapter/RestClient";

export function iacScanRequest(): IacScanRequest {
    const iacScanUseCase = new IacScanUseCase(new IacScanner(), new RestClient());
    return new IacScanRequest(iacScanUseCase);
}