import { ComponentFixture, TestBed } from '@angular/core/testing';

import { FileUploadFormComponent } from './file-upload-form.component';

describe('FileUploadFormComponent', () => {
  let component: FileUploadFormComponent;
  let fixture: ComponentFixture<FileUploadFormComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FileUploadFormComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(FileUploadFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
