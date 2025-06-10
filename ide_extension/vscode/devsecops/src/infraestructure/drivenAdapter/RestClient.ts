import { IRestClientGateway } from "../../domain/model/gateways/IRestClientGateway";

export class RestClient implements IRestClientGateway {

    constructor(){}

    async get(url: string, token?: string): Promise<unknown> {
        try{
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Basic ${token}`
                }
            });
            const data = await response.json();
            return data;
        }catch(error){
            console.error(error);
            throw new Error("Error fetching data to " + url);
        }
    }
    post(_url: string, _body: unknown): Promise<unknown> {
        throw new Error("Method not implemented.");
    }
    put(_url: string, _body: unknown): Promise<unknown> {
        throw new Error("Method not implemented.");
    }
    delete(_url: string): Promise<unknown> {
        throw new Error("Method not implemented.");
    }

}