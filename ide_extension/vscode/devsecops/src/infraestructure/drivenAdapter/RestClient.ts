import { IRestClientGateway } from "../../domain/model/gateways/IRestClientGateway";
import { AuthEncoder } from "../helper/AuthEncoder";

export class RestClient implements IRestClientGateway {

    constructor(){}

    async get(url: string, token: string): Promise<any> {
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
    post(url: string, body: any): Promise<any> {
        throw new Error("Method not implemented.");
    }
    put(url: string, body: any): Promise<any> {
        throw new Error("Method not implemented.");
    }
    delete(url: string): Promise<any> {
        throw new Error("Method not implemented.");
    }

}