import { Component, Input } from '@angular/core';
import { NgClass } from '@angular/common';
import { FormGroup, FormsModule, ReactiveFormsModule } from '@angular/forms';

import { TooltipComponent } from '@components/tooltip/tooltip.component';
import { InputValidationPipe } from '@shared/pipes/input-validation/input-validation.pipe';

@Component({
  selector: 'app-banner-form',
  standalone: true,
  imports: [
    NgClass,
    FormsModule,
    ReactiveFormsModule,
    TooltipComponent,
    InputValidationPipe,
  ],
  templateUrl: './banner-form.component.html',
  styleUrl: './banner-form.component.scss',
})
export class BannerFormComponent {
  @Input() parentForm!: FormGroup;
}
