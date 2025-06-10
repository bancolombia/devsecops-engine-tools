export default class DockerPathDetector { 

    static getDockerPath(): string {
        const dockerPath = process.env.DOCKER_PATH || "/usr/local/bin/docker";
        return dockerPath;
    }
    
}