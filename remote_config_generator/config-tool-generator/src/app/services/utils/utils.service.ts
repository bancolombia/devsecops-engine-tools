import { Injectable } from '@angular/core';
import { AbstractControl, FormArray, FormGroup } from '@angular/forms';

@Injectable({
  providedIn: 'root',
})
export class UtilsService {
  constructor() {}

  public getInputField(
    form: FormArray | FormGroup,
    name: string,
    index?: number
  ): AbstractControl | null | undefined {
    if (index === undefined) {
      form = form as FormGroup;
      return form.get(name) as FormGroup;
    }
    form = form as FormArray;
    return form.at(index).get(name);
  }
}
