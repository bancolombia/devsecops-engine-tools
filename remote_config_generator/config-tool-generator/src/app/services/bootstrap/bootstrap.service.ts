import { DOCUMENT } from '@angular/common';
import { Inject, Injectable } from '@angular/core';

//* Import Bootstrap
declare const bootstrap: any;

@Injectable({
  providedIn: 'root'
})
export class BootstrapService {

  constructor(@Inject(DOCUMENT) private readonly document: Document) {}

  public toggleTooltip(): void {
    Array.from(
      this.document.querySelectorAll('[data-bs-toggle="tooltip"]')
    ).forEach((tooltipNode) => new bootstrap.Tooltip(tooltipNode));
  }
}
