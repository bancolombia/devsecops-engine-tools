import { Component, inject } from '@angular/core';
import { AsyncPipe, JsonPipe, TitleCasePipe } from '@angular/common';
import { tap } from 'rxjs';

import { MainConfigToolFormComponent } from '@components/main-config-tool-form/main-config-tool-form.component';
import { ConfigToolService } from '@services/config-tool/config-tool.service';
import { IConfigTool } from '@core/models';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [AsyncPipe, JsonPipe, TitleCasePipe, MainConfigToolFormComponent],
  templateUrl: './home.component.html',
  styleUrl: './home.component.scss',
})
export default class HomeComponent {
  private readonly _configToolService = inject(ConfigToolService);

  configTool$ = this._configToolService.getConfigTool();
  configTool!: IConfigTool;
  fileName = 'ConfigTool';
  keysConfigEngine!: string[];
  keysEngine!: string[];
  keyValueconfigTool!: [string, any][];

  ngOnInit(): void {
    this.getConfigTool();
  }

  private getConfigTool(): void {
    const configTool$ = this._configToolService.getConfigTool().pipe(
      tap((res) => {
        this.configTool = res;
      })
    );
    configTool$.subscribe();
  }
}
