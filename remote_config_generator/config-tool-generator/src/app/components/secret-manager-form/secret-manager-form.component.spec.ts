import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SecretManagerFormComponent } from './secret-manager-form.component';

describe('SecretManagerFormComponent', () => {
  let component: SecretManagerFormComponent;
  let fixture: ComponentFixture<SecretManagerFormComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SecretManagerFormComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(SecretManagerFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
