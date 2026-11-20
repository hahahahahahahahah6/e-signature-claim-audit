"""Static documentation and source inspection."""
import ast
import os
import re
from pathlib import Path
from .phrases import ESIGNATURE, NOESIGNATURE

GENERIC = frozenset('send_signature_request send_signature_requests create_signature_request request_signature request_signatures collect_signature collect_signatures sign_document sign_documents sign_file sign_contract send_for_signature send_document_for_signature send_envelope sign_envelope initiate_signature_request create_signing_request send_signing_request request_electronic_signature collect_electronic_signature send_electronic_signature_request create_electronic_signature_request request_document_signature capture_signature'.split())

def normalize(text):
    text = text.lower().replace('’', "'")
    text = re.sub(r"n['’]t\b", ' not', text)
    return ' '.join(text.replace('-', ' ').split())

def patterns(phrases):
    return [(p, re.compile(r'(?<!\w)' + re.escape(p) + r'(?!\w)')) for p in sorted(phrases, key=lambda x: (-len(x), x))]

YES = patterns(ESIGNATURE)
NO = patterns(NOESIGNATURE)

def claims(text):
    lines = []
    fence = None
    for line in text.splitlines():
        m = re.match(r'^ {0,3}(`{3,}|~{3,})(.*)$', line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not m.group(2).strip():
                fence = None
            continue
        if m:
            fence = m.group(1)
            continue
        lines.append(line)
    yes = no = False
    for para in re.split(r'\n\s*\n', '\n'.join(lines)):
        value = normalize(para)
        for _, pattern in NO:
            value, count = pattern.subn(' ', value)
            no |= bool(count)
        yes |= any(pattern.search(value) for _, pattern in YES)
    return yes, no

def evidence(text):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    nodes = list(ast.walk(tree))
    shadows = {n.name for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    imports = {}
    for n in nodes:
        if isinstance(n, ast.Import):
            for a in n.names:
                imports[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
        elif isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                if a.name != '*':
                    imports[a.asname or a.name] = n.module + '.' + a.name
    bound = set()
    def names(target):
        if isinstance(target, ast.Name):
            bound.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts: names(item)
    for n in nodes:
        if isinstance(n, ast.Assign):
            for t in n.targets: names(t)
        elif isinstance(n, ast.AnnAssign): names(n.target)
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if item.optional_vars: names(item.optional_vars)
    for name in shadows | bound:
        imports.pop(name, None)
    calls = [n for n in nodes if isinstance(n, ast.Call)]
    def route(f, target):
        if isinstance(f, ast.Name):
            return f.id not in shadows and imports.get(f.id) == target
        if isinstance(f, ast.Attribute) and f.attr == target.rsplit('.', 1)[-1] and f.attr not in shadows:
            base = f.value
            chain = []
            while isinstance(base, ast.Attribute):
                chain.append(base.attr)
                base = base.value
            if isinstance(base, ast.Name) and base.id not in shadows and base.id in imports:
                path = imports[base.id] + ('.' + '.'.join(reversed(chain)) if chain else '')
                prefix = target.rsplit('.', 1)[0]
                return path == prefix or path.startswith(prefix + '.')
        return False
    def attr(call, names):
        return isinstance(call.func, ast.Attribute) and call.func.attr in names and call.func.attr not in shadows
    def has(target):
        return any(route(c.func, target) for c in calls)
    direct = {'create_envelope', 'signature_request_send', 'signature_request_send_with_template', 'signature_request_create_embedded', 'signature_request_create_embedded_with_template', 'signature_request_bulk_send_with_template', 'signature_request_bulk_create_embedded_with_template', 'sign_pdf'}
    if any(attr(c, direct) for c in calls): return True
    if has('pyhanko.sign.signers.sign_pdf') or has('endesive.pdf.cms.sign'): return True
    if any(has(t) for t in ('eversign.Client', 'eversign.client.Client')) and any(attr(c, {'create_document', 'create_document_from_template'}) for c in calls): return True
    hello = ('HelloSignSignature', 'HelloSignEmbeddedDocumentSignature', 'HelloSignUnclaimedDraftDocumentSignature')
    if any(has(prefix + name) for prefix in ('hellosign.', 'hellosign.hellosign.') for name in hello) and any(attr(c, {'create'}) for c in calls): return True
    for c in calls:
        f = c.func
        if isinstance(f, ast.Attribute) and f.attr in GENERIC and f.attr not in shadows: return True
        if isinstance(f, ast.Name) and f.id not in shadows and imports.get(f.id, '').rsplit('.', 1)[-1] in GENERIC: return True
    return False

def audit(root='.', ignore=()):
    root = Path(root)
    if root.is_symlink() or not root.is_dir(): raise OSError('repository is not a directory: ' + str(root))
    yes = no = prod = test = False
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=lambda e: (_ for _ in ()).throw(e)):
        base = Path(directory)
        dirs[:] = [d for d in dirs if not (base / d).is_symlink() and not any((base / d).relative_to(root).as_posix().startswith(p) for p in ignore)]
        for filename in files:
            path = base / filename
            rel = path.relative_to(root)
            if path.is_symlink() or any(rel.as_posix().startswith(p) for p in ignore): continue
            parts = rel.parts
            if (len(parts) == 1 and filename == 'README.md') or ('docs' in parts[:-1] and filename.endswith('.md')):
                y, n = claims(path.read_text(encoding='utf-8')); yes |= y; no |= n
            if filename.endswith('.py') and not set(parts[:-1]) & {'fixtures', 'docs', 'examples'}:
                found = evidence(path.read_text(encoding='utf-8'))
                is_test = 'tests' in parts[:-1] or filename.startswith('test_') or filename.endswith('_test.py')
                if is_test: test |= found
                else: prod |= found
    findings = []
    if yes and not prod:
        findings.append({'id': 'documented-e-signature-claim-false', 'severity': 'MEDIUM' if test else 'HIGH', 'message': 'Documented capability has evidence only in tests.' if test else 'Documented capability has no production evidence.'})
    if no and prod:
        findings.append({'id': 'documented-no-e-signature-claim-false', 'severity': 'HIGH', 'message': 'Documented denial conflicts with production evidence.'})
    return {'verdict': 'FAIL' if findings else 'PASS', 'findings': findings}
