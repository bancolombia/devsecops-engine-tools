import { ComponentFixture, TestBed } from '@angular/core/testing';

import { MainConfigToolFormComponent } from './main-config-tool-form.component';

describe('MainConfigToolFormComponent', () => {
  let component: MainConfigToolFormComponent;
  let fixture: ComponentFixture<MainConfigToolFormComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MainConfigToolFormComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(MainConfigToolFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
