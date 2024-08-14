import { InputValidationPipe } from './input-validation.pipe';

describe('InputValidationPipe', () => {
  it('create an instance', () => {
    const pipe = new InputValidationPipe();
    expect(pipe).toBeTruthy();
  });
});
