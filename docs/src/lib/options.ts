import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

export interface OptionValue {
  _type: 'literalExpression' | 'literalMD';
  text: string;
}
export interface Option {
  name: string;
  description: string | null;
  type: string;
  default?: OptionValue;
  example?: OptionValue;
  declarations: string[];
}

// One evaluation per build/server process, shared by every Options component.
// The promise also shares failures; no generated files or persistent cache.
let options: Promise<Option[]> | undefined;
export function getOptions(): Promise<Option[]> {
  return options ??= Promise.resolve().then(() => JSON.parse(execFileSync(
    'nix',
    [
      '--extra-experimental-features', 'nix-command flakes',
      'eval', '--impure', '--json', '--read-only',
      '--option', 'allow-import-from-derivation', 'false',
      '--file', resolve('options.nix'),
    ],
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
  )));
}
export const optionId = (name: string) => name.toLowerCase().replaceAll('.', '-').replace(/[<>*]/g, '');

// Keep labels local to the option group, while preserving full paths and IDs.
export function optionLabel(name: string, prefix: string): string {
  if (name.startsWith(prefix + '.')) {
    return name.slice(prefix.length + 1).replace(/^<name>\./, '');
  }
  return name.replace(/^networking\.nftables\.(firewall\.)?/, '');
}
