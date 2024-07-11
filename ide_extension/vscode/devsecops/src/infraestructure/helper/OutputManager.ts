export default class OutputManager {

    static removeAnsiEscapeCodes(text: string): string {
        return text.replace(/\x1b\[[0-9;]*m/g, '');
    }

}