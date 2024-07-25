import { getPassword, setPassword } from "keytar";

export interface ICredentials {
  service: string;
  account: string;
  password: string | null;
}

export default class SecretManager {
  static storeCredential(credential: ICredentials): void {
    setPassword(
      credential.service,
      credential.account,
      credential.password ?? ""
    );
  }

  static getCredential(credential: ICredentials): Promise<string | null> {
    return getPassword(credential.service, credential.account).then(
      (password) => password
    );
  }
}
