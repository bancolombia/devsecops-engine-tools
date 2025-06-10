export interface IRestClientGateway {
    get(url: string, token: string): Promise<unknown>;
    post(url: string, body: unknown): Promise<unknown>;
    put(url: string, body: unknown): Promise<unknown>;
    delete(url: string): Promise<unknown>;
}