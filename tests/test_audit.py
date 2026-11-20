import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from e_signature_claim_audit.audit import audit, claims, evidence, GENERIC
from e_signature_claim_audit.phrases import ESIGNATURE, NOESIGNATURE
from e_signature_claim_audit.__main__ import main

EXPECTED_YES = ('signs documents', 'sign documents', 'signs a document', 'sign a document', 'signs document', 'sign document', 'e signature support', 'supports e signature', 'supports signing documents', 'supports signing a document', 'e signature feature', 'e signature functionality', 'e signature capability', 'e signature capabilities', 'e signature', 'signs documents with docusign', 'sign documents with docusign', 'signs documents with hellosign', 'sign documents with hellosign', 'signs documents with dropbox sign', 'sign documents with dropbox sign', 'signs documents with adobe sign', 'sign documents with adobe sign', 'signs documents with signnow', 'sign documents with signnow', 'signs documents with pandadoc', 'sign documents with pandadoc', 'collects electronic signatures', 'collect electronic signatures', 'collects an electronic signature', 'collect an electronic signature', 'collects signatures', 'collect signatures', 'requests signatures', 'request signatures', 'requests a signature', 'request a signature', 'sends documents for signature', 'send documents for signature', 'sends a document for signature', 'send a document for signature', 'electronic signature support', 'supports electronic signatures', 'supports electronic signature', 'electronic signature feature', 'electronic signature functionality', 'electronic signature capability', 'electronic signature capabilities', 'electronic signatures', 'electronic signature')
EXPECTED_NO = ('does not sign documents', 'never signs documents', 'does not sign a document', 'never signs a document', 'does not sign document', 'never signs document', 'no e signature support', 'does not support e signature', 'never supports e signature', 'never supports signing documents', 'no e signature feature', 'no e signature functionality', 'no e signature capability', 'does not sign documents with docusign', 'never signs documents with docusign', 'does not sign documents with hellosign', 'never signs documents with hellosign', 'does not collect electronic signatures', 'never collects electronic signatures', 'does not request signatures', 'never requests signatures', 'no electronic signature', 'does not send documents for signature', 'never sends documents for signature')

class AuditTests(unittest.TestCase):
    def test_phrase_oracle(self):
        self.assertEqual(ESIGNATURE, EXPECTED_YES)
        self.assertEqual(NOESIGNATURE, EXPECTED_NO)
        for phrase in EXPECTED_YES: self.assertEqual(claims(phrase), (True, False))
        for phrase in EXPECTED_NO: self.assertEqual(claims(phrase), (False, True))
    def test_routes(self):
        cases = ['x.create_envelope()', 'from docusign_esign import EnvelopesApi; EnvelopesApi().create_envelope()', 'import eversign; eversign.Client(); x.create_document()', 'import eversign.client; eversign.client.Client(); x.create_document_from_template()', 'from eversign import Client as C; C(); x.create_document()', 'x.sign_pdf()', 'from pyhanko.sign.signers import sign_pdf as s; s()', 'import pyhanko; pyhanko.sign.signers.PdfSigner().sign_pdf()', 'import endesive.pdf.cms; endesive.pdf.cms.sign()', 'from endesive.pdf.cms import sign as s; s()', 'from x import send_signature_request as s; s()']
        cases += ['x.' + name + '()' for name in GENERIC]
        cases += ['x.' + name + '()' for name in ('signature_request_send', 'signature_request_send_with_template', 'signature_request_create_embedded', 'signature_request_create_embedded_with_template', 'signature_request_bulk_send_with_template', 'signature_request_bulk_create_embedded_with_template')]
        for name in ('HelloSignSignature', 'HelloSignEmbeddedDocumentSignature', 'HelloSignUnclaimedDraftDocumentSignature'):
            cases.extend(['import hellosign; hellosign.'+name+'(); x.create()', 'from hellosign.hellosign import '+name+' as H; H(); x.create()'])
        for code in cases:
            with self.subTest(code=code): self.assertTrue(evidence(code))
    def test_non_evidence(self):
        cases = ['import docusign_esign', 'from docusign_esign import EnvelopesApi; EnvelopesApi()', 'x.ApiClient()', 'x.SignatureRequestApi()', 'import eversign; eversign.Client()', 'x.create_document()', 'import hellosign; hellosign.HelloSignSignature()', 'x.create()', 'x.PdfSigner()', 'x.create_template()', 'x.get_envelope()', 'x.signature_request_get()', 'x.signature_request_cancel()', 'x.signature_request_remind()', 'x.signature_request_list()', 'x.get_all_documents()', 'x.send_reminder_for_document()', 'x.cancel_document()', 'x.upload_file()', 'x.detail()', 'x.validate_pdf_signature()', 'x.stamp()', 'import endesive.pdf; endesive.pdf.verify()', 'import endesive.plain; endesive.plain.sign()', 'def sign_document(): pass\nsign_document()', 'def create_envelope(): pass\nx.create_envelope()', "'signs documents'", 'import requests; requests.post("https://api.docusign.net/restapi/v2.1/accounts/x/envelopes")', 'import subprocess; subprocess.run(["docusign"])', 'mindee.parse(x)', 'x.begin_analyze_document("prebuilt-layout")', 'veryfi.Client()', 'documentai.process_document()', 'textract.analyze_document()', 'eden.universal_ai()', 'llamaparse.parse()', 'nanonets.ocr(model_id="opaque")', 'docsumo.upload()', 'from x import sign_document; sign_document = x; sign_document()', 'from endesive.pdf.cms import sign; with x as sign: pass\nsign()', 'import hellosign; hellosign.HelloSignEmbeddedDocumentSigningUrl(); x.create()', 'broken syntax !']
        for code in cases:
            with self.subTest(code=code): self.assertFalse(evidence(code))
    def test_findings(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); readme=p/'README.md'; readme.write_text('signs documents')
            result=audit(p); self.assertEqual(result['findings'][0]['id'], 'documented-e-signature-claim-false'); self.assertEqual(result['findings'][0]['severity'], 'HIGH'); self.assertEqual(main(['audit',d]),2)
            (p/'tests').mkdir(); (p/'tests/test_x.py').write_text('x.sign_document()')
            self.assertEqual(audit(p)['findings'][0]['severity'],'MEDIUM'); self.assertEqual(main(['audit',d]),0); self.assertEqual(main(['audit',d,'--fail-on','medium']),2)
            (p/'app.py').write_text('x.sign_document()'); self.assertEqual(audit(p)['verdict'],'PASS')
            readme.write_text('does not sign documents'); self.assertEqual(audit(p)['findings'][0]['id'],'documented-no-e-signature-claim-false'); self.assertEqual(main(['audit',d]),2)
            (p/'app.py').unlink(); self.assertEqual(audit(p)['verdict'],'PASS')
            readme.write_text('nothing claimed'); self.assertEqual(audit(p)['verdict'],'PASS')
            readme.write_text('```\nsigns documents\n```'); self.assertEqual(audit(p)['verdict'],'PASS')
            readme.write_text('`signs documents`'); self.assertEqual(audit(p)['findings'][0]['severity'],'MEDIUM')
    def test_split_ignore_and_symlink(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            p=Path(d); (p/'README.md').write_text('signs documents'); (p/'a.py').write_text('import eversign; eversign.Client()'); (p/'b.py').write_text('x.create_document()')
            self.assertEqual(audit(p)['verdict'],'FAIL')
            (p/'b.py').write_text('x.sign_document()'); self.assertEqual(audit(p)['verdict'],'PASS'); self.assertEqual(audit(p,['b.py'])['verdict'],'FAIL')
            (p/'b.py').unlink(); target=Path(outside)/'x.py'; target.write_text('x.sign_document()'); (p/'link.py').symlink_to(target); self.assertEqual(audit(p)['verdict'],'FAIL')
    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'README.md').write_text('signs documents')
            r=subprocess.run([sys.executable,'-m','e_signature_claim_audit','audit',d,'--json'],capture_output=True,text=True)
            self.assertEqual(r.returncode,2); data=json.loads(r.stdout); self.assertEqual(data['verdict'],'FAIL'); self.assertTrue(data['findings'][0]['message'])
            self.assertEqual(main(['audit',d,'--ignore','README.md']),0)
        with self.assertRaises(SystemExit) as cm: main(['--version'])
        self.assertEqual(cm.exception.code,0)

if __name__ == '__main__': unittest.main()
