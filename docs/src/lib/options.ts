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
// Submodule selectors can include <name>; labels retain those placeholders
// and nested fields while omitting the shared collection path.
export function optionLabel(name: string, prefix: string): string {
  const groupPrefix = prefix.replace(/(?:\.<name>)+$/, '');
  const namespace = 'networking.nftables.firewall.';
  if (groupPrefix === 'networking.nftables.chains') {
    return name === groupPrefix ? '...chains' : '...' + name.slice(groupPrefix.length + 1);
  }
  const snippets = namespace + 'snippets.';
  if (name.startsWith(snippets)) return '...' + name.slice(snippets.length);
  if (!name.startsWith(namespace)) return name;
  const submodulePrefix = groupPrefix + '.<name>.';
  const relative = name.startsWith(submodulePrefix)
    ? name.slice(groupPrefix.length + 1)
    : name.slice(namespace.length);
  return '...' + relative;
}
