import { Pipe, PipeTransform, inject } from '@angular/core';
import { FormArray, FormGroup } from '@angular/forms';

import { UtilsService } from '@services/utils/utils.service';

@Pipe({
  name: 'inputValidation',
  standalone: true,
  pure: false,
})
export class InputValidationPipe implements PipeTransform {
  private readonly _utilsService = inject(UtilsService)

  transform(
    form: FormArray | FormGroup,
    name: string,
    index?: number
  ): 'is-valid' | 'is-invalid' | undefined {
    const input = this._utilsService.getInputField(form, name, index);
    if (!input) return undefined;
    if (input.touched) {
      return input.valid ? 'is-valid' : 'is-invalid';
    }
    return undefined;
  }
}
