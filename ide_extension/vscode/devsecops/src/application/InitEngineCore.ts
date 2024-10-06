import { IacScanner } from "../infraestructure/drivenAdapter/IacScanner";
import { IacScanRequest } from "../infraestructure/entryPoint/IacScanRequest";
import { IacScanUseCase } from "../domain/usecase/IacScanUseCase";
import { RestClient } from "../infraestructure/drivenAdapter/RestClient";
import { SecretScanUseCase } from "../domain/usecase/SecretScanUseCase";
import { SecretScanRequest } from "../infraestructure/entryPoint/SecretScanRequest";

export function iacScanRequest(): IacScanRequest {
    const iacScanUseCase = new IacScanUseCase(new IacScanner(), new RestClient());
    return new IacScanRequest(iacScanUseCase);
}

export function secretScanRequest(): SecretScanRequest {
    const secretScanUseCase = new SecretScanUseCase(new IacScanner(), new RestClient());
    return new SecretScanRequest(secretScanUseCase);
}