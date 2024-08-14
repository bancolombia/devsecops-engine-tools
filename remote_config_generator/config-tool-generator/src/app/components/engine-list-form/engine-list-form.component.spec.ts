import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EngineListFormComponent } from './engine-list-form.component';

describe('EngineListFormComponent', () => {
  let component: EngineListFormComponent;
  let fixture: ComponentFixture<EngineListFormComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EngineListFormComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(EngineListFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
