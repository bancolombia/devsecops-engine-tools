import { TestBed } from '@angular/core/testing';

import { ConfigToolService } from './config-tool.service';

describe('ConfigToolService', () => {
  let service: ConfigToolService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(ConfigToolService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
