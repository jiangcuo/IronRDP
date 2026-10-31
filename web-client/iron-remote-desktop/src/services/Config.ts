import type { DesktopSize } from '../interfaces/DesktopSize';
import type { Extension } from '../interfaces/Extension';

export class Config {
    readonly username: string;
    readonly password: string;
    readonly destination: string;
    readonly proxyAddress: string;
    readonly webSocketProtocols?: string[];
    readonly serverDomain: string;
    readonly authToken: string;
    readonly desktopSize?: DesktopSize;
    readonly extensions: Extension[];
    readonly webSocketUrl?: string;

    constructor(
        userData: { username: string; password: string },
        proxyData: { address: string; authToken: string },
        configOptions: {
            destination: string;
            serverDomain: string;
            webSocketProtocols?: string[];
            extensions: Extension[];
            desktopSize?: DesktopSize;
            webSocketUrl?: string;
        },
    ) {
        this.username = userData.username;
        this.password = userData.password;
        this.proxyAddress = proxyData.address;
        this.authToken = proxyData.authToken;
        this.destination = configOptions.destination;
        this.serverDomain = configOptions.serverDomain;
        this.webSocketProtocols = configOptions.webSocketProtocols ?? [];
        this.extensions = configOptions.extensions;
        this.desktopSize = configOptions.desktopSize;
        this.webSocketUrl = configOptions.webSocketUrl;
    }
}
