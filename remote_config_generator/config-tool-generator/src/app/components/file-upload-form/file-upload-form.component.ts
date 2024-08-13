import { Component, EventEmitter, Output, inject } from '@angular/core';
import { tap } from 'rxjs';

import { TooltipComponent } from '@components/tooltip/tooltip.component';
import { ConfigToolService } from '@services/config-tool/config-tool.service';
import { IConfigToolEngineForm } from '@core/models';

@Component({
  selector: 'app-file-upload-form',
  standalone: true,
  imports: [TooltipComponent],
  templateUrl: './file-upload-form.component.html',
  styleUrl: './file-upload-form.component.scss',
})
export class FileUploadFormComponent {
  private readonly _configToolService = inject(ConfigToolService);

  public status: 'initial' | 'uploading' | 'success' | 'fail' = 'initial';
  public file: File | null = null;
  private inputFile!: HTMLInputElement;

  @Output() configToolEngineForm = new EventEmitter<IConfigToolEngineForm>();

  public onChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    this.inputFile = input;
    if (!input.files?.length) {
      return;
    }
    const file: File = input.files[0];
    const isTypeJson =
      'application/json' === `${file?.type}` && file.name.endsWith('.json');
    if (!isTypeJson) {
      this.status = 'fail';
      input.value = '';
      return;
    }
    this.status = 'success';
    this.file = file;
  }

  public async onUpload(): Promise<void> {
    const res = await this.file?.text();
    try {
      const configTool = JSON.parse(`${res}`);
      const configToolEngineForm =
        this._configToolService.setInitConfigTool(configTool);
      this.configToolEngineForm.emit(configToolEngineForm);
      this.status = 'initial';
      this.file = null;
    } catch (error) {
      if (error instanceof SyntaxError) {
        const errorMessage = error?.message;
        console.error('Sintaxis error:', errorMessage);
      } else {
        throw error;
      }
    }
  }

  public onClear(): void {
    const initConfigTool$ = this._configToolService.getInitConfigTool().pipe(
      tap((res) => {
        this.configToolEngineForm.emit(res);
      })
    );
    initConfigTool$.subscribe();
    this.status = 'initial';
    this.inputFile.value = '';
  }
}
