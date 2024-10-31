import { IacScanner } from "../infraestructure/drivenAdapter/IacScanner";
import { IacScanRequest } from "../infraestructure/entryPoint/IacScanRequest";
import { IacScanUseCase } from "../domain/usecase/IacScanUseCase";
import { RestClient } from "../infraestructure/drivenAdapter/RestClient";
import { ImageScanRequest } from "../infraestructure/entryPoint/ImageScanRequest";
import { ImageScanner } from "../infraestructure/drivenAdapter/ImageScanner";
import { ImageScanUseCase } from "../domain/usecase/ImageScanUseCase";

export function iacScanRequest(): IacScanRequest {
    const iacScanUseCase = new IacScanUseCase(new IacScanner(), new RestClient());
    return new IacScanRequest(iacScanUseCase);
}

export function imageScanRequest(): ImageScanRequest{
    const imageScanUseCase = new ImageScanUseCase(new ImageScanner());
    return new ImageScanRequest(imageScanUseCase);
}