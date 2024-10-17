import { AfterViewInit, Component, Input, inject } from '@angular/core';

import { BootstrapService } from '@services/bootstrap/bootstrap.service';

@Component({
  selector: 'app-tooltip',
  standalone: true,
  imports: [],
  templateUrl: './tooltip.component.html',
  styleUrl: './tooltip.component.scss',
})
export class TooltipComponent implements AfterViewInit {
  private readonly _bootstrapService = inject(BootstrapService);

  public isVisible = true;

  @Input() icon = 'bi-info-circle';
  @Input() fontSize = '0.8rem';
  @Input() tooltipTitle = '';

  ngAfterViewInit(): void {
    this._bootstrapService.toggleTooltip();
  }
}
