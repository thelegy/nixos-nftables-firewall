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

// Abbreviate the firewall namespace and the shared Chains collection path.
// Submodule pages can additionally
// omit their shared group path, but keep <name> and all nested fields visible.
export function optionLabel(name: string, prefix: string): string {
  const namespace = 'networking.nftables.firewall.';
  if (prefix === 'networking.nftables.chains') {
    return name === prefix ? '...chains' : '...' + name.slice(prefix.length + 1);
  }
  const snippets = namespace + 'snippets.';
  if (name.startsWith(snippets)) return '...' + name.slice(snippets.length);
  if (!name.startsWith(namespace)) return name;
  const submodulePrefix = prefix + '.<name>.';
  const relative = name.startsWith(submodulePrefix)
    ? name.slice(prefix.length + 1)
    : name.slice(namespace.length);
  return '...' + relative;
}
