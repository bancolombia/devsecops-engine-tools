import { Component, Input, OnInit, inject } from '@angular/core';
import { FormGroup, FormsModule, ReactiveFormsModule } from '@angular/forms';
import { TitleCasePipe, JsonPipe } from '@angular/common';
import { tap } from 'rxjs';

import { TooltipComponent } from '@components/tooltip/tooltip.component';
import { ConfigToolService } from '@services/config-tool/config-tool.service';
import { IConfigToolEngineList } from '@core/models';

@Component({
  selector: 'app-engine-list-form',
  standalone: true,
  imports: [TitleCasePipe, JsonPipe, FormsModule, ReactiveFormsModule, TooltipComponent],
  templateUrl: './engine-list-form.component.html',
  styleUrl: './engine-list-form.component.scss',
})
export class EngineListFormComponent implements OnInit {
  private readonly _configToolService = inject(ConfigToolService);

  @Input() parentForm!: FormGroup;

  configToolEngineList!: IConfigToolEngineList;

  ngOnInit(): void {
    this.getConfigTool();
  }

  private getConfigTool(): void {
    this._configToolService.getConfigTool().pipe(
      tap((res) => {
        this.configToolEngineList = res;
        this.getKeys(res);

      })
    ).subscribe();
  }

  private getKeys(configToolEngineList: IConfigToolEngineList): void {
    const engineList = configToolEngineList.ENGINE_LIST?.map(
      ({ ENGINE_NAME }) => ENGINE_NAME
    );
    const engineListKey = [...new Set(engineList)];
  }

  public getEngineIACFormGroup(): FormGroup {
    return this.parentForm.get('ENGINE_IAC') as FormGroup;
  }
}
