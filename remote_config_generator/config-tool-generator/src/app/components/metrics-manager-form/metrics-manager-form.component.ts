import { Component, Input } from '@angular/core';
import { NgClass } from '@angular/common';
import { FormGroup, FormsModule, ReactiveFormsModule } from '@angular/forms';

import { TooltipComponent } from '@components/tooltip/tooltip.component';
import { InputValidationPipe } from '@shared/pipes/input-validation/input-validation.pipe';

@Component({
  selector: 'app-metrics-manager-form',
  standalone: true,
  imports: [
    NgClass,
    FormsModule,
    ReactiveFormsModule,
    TooltipComponent,
    InputValidationPipe,
  ],
  templateUrl: './metrics-manager-form.component.html',
  styleUrl: './metrics-manager-form.component.scss',
})
export class MetricsManagerFormComponent {

  @Input() parentForm!: FormGroup;

  public getAWSFormGroup(): FormGroup {
    return this.parentForm.get('AWS') as FormGroup;
  }
}
