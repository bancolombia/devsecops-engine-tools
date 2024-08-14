import { ComponentFixture, TestBed } from '@angular/core/testing';

import { MetricsManagerFormComponent } from './metrics-manager-form.component';

describe('MetricsManagerFormComponent', () => {
  let component: MetricsManagerFormComponent;
  let fixture: ComponentFixture<MetricsManagerFormComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MetricsManagerFormComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(MetricsManagerFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
