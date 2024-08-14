import { Component, ElementRef, ViewChild, inject } from '@angular/core';
import { NgClass } from '@angular/common';
import {
  FormBuilder,
  FormGroup,
  FormsModule,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms';
import { JsonPipe } from '@angular/common';
import { DomSanitizer, SafeUrl } from '@angular/platform-browser';

import { BannerFormComponent } from '@components/banner-form/banner-form.component';
import { SecretManagerFormComponent } from '@components/secret-manager-form/secret-manager-form.component';
import { VulnerabilityManagerFormComponent } from '@components/vulnerability-manager-form/vulnerability-manager-form.component';
import { MetricsManagerFormComponent } from '@components/metrics-manager-form/metrics-manager-form.component';
import { EngineListFormComponent } from '@components/engine-list-form/engine-list-form.component';
import { FileUploadFormComponent } from '@components/file-upload-form/file-upload-form.component';
import { IConfigTool, IConfigToolEngineForm, IEngine } from '@core/models';

@Component({
  selector: 'app-main-config-tool-form',
  standalone: true,
  imports: [
    NgClass,
    JsonPipe,
    FormsModule,
    ReactiveFormsModule,
    BannerFormComponent,
    SecretManagerFormComponent,
    VulnerabilityManagerFormComponent,
    MetricsManagerFormComponent,
    EngineListFormComponent,
    FileUploadFormComponent,
  ],
  templateUrl: './main-config-tool-form.component.html',
  styleUrl: './main-config-tool-form.component.scss',
})
export class MainConfigToolFormComponent {
  private readonly _fb = inject(FormBuilder);
  private readonly _sanitizer = inject(DomSanitizer);

  @ViewChild('downloadFile') private downloadFile!: ElementRef;

  public configToolEngineForm!: IConfigToolEngineForm;
  public fileName = 'ConfigTool';

  public mainForm = this._fb.nonNullable.group({
    BANNER: ['', Validators.required],
    SECRET_MANAGER: this._fb.group({
      AWS: this._fb.group({
        SECRET_NAME: ['', Validators.required],
        ROLE_ARN: ['', Validators.required],
        REGION_NAME: ['', Validators.required],
      }),
    }),
    VULNERABILITY_MANAGER: this._fb.group({
      BRANCH_FILTER: ['', Validators.required],
      DEFECT_DOJO: this._fb.group({
        CMDB_MAPPING_PATH: ['', Validators.required],
        HOST_CMDB: ['', Validators.required],
        HOST_DEFECT_DOJO: ['', Validators.required],
        REGEX_EXPRESSION_CMDB: ['', Validators.required],
        LIMITS_QUERY: [999, Validators.required],
      }),
    }),
    METRICS_MANAGER: this._fb.group({
      AWS: this._fb.group({
        BUCKET: ['', Validators.required],
        ROLE_ARN: ['', Validators.required],
        REGION_NAME: ['', Validators.required],
      }),
    }),
    ENGINE_IAC: ['NONE', Validators.required],
    ENGINE_CONTAINER: ['NONE', Validators.required],
    ENGINE_DAST: ['NONE', Validators.required],
    ENGINE_SECRET: ['NONE', Validators.required],
    ENGINE_DEPENDENCIES: ['NONE', Validators.required],
  });

  private downloadFileReport(): void {
    setTimeout(() => this.downloadFile.nativeElement.click(), 200);
  }

  public getSecretManagerFormGroup(): FormGroup {
    return this.mainForm.controls.SECRET_MANAGER;
  }

  public getFormGroup(name: string): FormGroup {
    return this.mainForm.get(name) as FormGroup;
  }

  public downloadConfigTool(): SafeUrl {
    const configTool = JSON.stringify(this.setConfigTool());
    return this._sanitizer.bypassSecurityTrustUrl(
      'data:text/json;charset=UTF-8,' + encodeURIComponent(configTool)
    );
  }

  private getEngine(tool: string): IEngine {
    return {
      ENABLED: `${tool !== 'NONE'}`,
      TOOL: tool,
    };
  }

  private setConfigTool(): IConfigTool {
    const {
      ENGINE_IAC,
      ENGINE_CONTAINER,
      ENGINE_DAST,
      ENGINE_SECRET,
      ENGINE_DEPENDENCIES,
      ...data
    } = this.mainForm.getRawValue();

    return {
      ...data,
      ENGINE_IAC: {
        ...this.getEngine(ENGINE_IAC),
      },
      ENGINE_CONTAINER: {
        ...this.getEngine(ENGINE_CONTAINER),
      },
      ENGINE_DAST: {
        ...this.getEngine(ENGINE_DAST),
      },
      ENGINE_SECRET: {
        ...this.getEngine(ENGINE_SECRET),
      },
      ENGINE_DEPENDENCIES: {
        ...this.getEngine(ENGINE_DEPENDENCIES),
      },
    } as IConfigTool;
  }

  public onSubmit() {
    this.mainForm.markAllAsTouched();
    if (this.mainForm.valid) {
      this.downloadFileReport();
    }
  }

  public configToolEngineFormEvent(event: IConfigToolEngineForm): void {
    this.mainForm.patchValue({ ...event });
  }
}
