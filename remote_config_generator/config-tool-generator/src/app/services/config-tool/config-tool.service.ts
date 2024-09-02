import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map } from 'rxjs';

import { IConfigTool, IConfigToolEngineForm } from '@core/models';
import { environment } from '@environments/environment';

@Injectable({
  providedIn: 'root',
})
export class ConfigToolService {
  private readonly url = environment.url;
  private readonly _http = inject(HttpClient);

  public getConfigTool(): Observable<IConfigTool> {
    return this._http.get<IConfigTool>(`${this.url}/ConfigToolInput.json`);
  }

  public getInitConfigTool(id = 0): Observable<IConfigToolEngineForm> {
    return this._http
      .get<IConfigTool>(`${this.url}/ConfigTool.json`)
      .pipe(map((res) => this.setInitConfigTool(res)));
  }

  public setInitConfigTool(value: IConfigTool) {
    const {
      ENGINE_IAC,
      ENGINE_CONTAINER,
      ENGINE_DAST,
      ENGINE_SECRET,
      ENGINE_DEPENDENCIES,
      ...data
    } = value;
    return {
      ...data,
      ENGINE_IAC: value.ENGINE_IAC?.TOOL,
      ENGINE_CONTAINER: ENGINE_CONTAINER?.TOOL,
      ENGINE_DAST: ENGINE_DAST?.TOOL,
      ENGINE_SECRET: ENGINE_SECRET?.TOOL,
      ENGINE_DEPENDENCIES: ENGINE_DEPENDENCIES?.TOOL,
    };
  }
}
