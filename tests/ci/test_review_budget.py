"""Offline adapter tests: no credentials, sockets, CLI API calls, or deployments."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'.github/scripts'))
import review_budget as b
import budget_policy as p

HEAD='a'*40
BASE='b'*40
BOT=dict(p.BOT)


def evidence():
    return dict(pr=dict(head={'sha':HEAD},base={'sha':BASE},state='open',draft=False,mergeable=True),
                comments=[], reviews=[], reactions=[], threads=[], summary=None,
                findings=[], unresolved=[], completed=None, security_clear=True,
                newer=False,native_ok=True,merge_state='CLEAN')


class AdapterTests(unittest.TestCase):
    def test_all_api_writes_are_json_and_scoped(self):
        result=type('Result',(),dict(returncode=0,stdout='{"id":1}'))()
        with patch.object(b.subprocess,'run',return_value=result) as call:
            b.api(b.PREFIX+'/issues','POST',{'body':'$(secret)\n`literal`'})
        self.assertEqual(json.loads(call.call_args.kwargs['input'])['body'],'$(secret)\n`literal`')
        self.assertNotIn('shell',call.call_args.kwargs)
        with self.assertRaises(b.Blocked): b.api('repos/other/repo/issues','POST',{})

    def test_api_denial_does_not_retry(self):
        result=type('Result',(),dict(returncode=1,stdout=''))()
        with patch.object(b.subprocess,'run',return_value=result) as call,self.assertRaises(b.Blocked):
            b.api(b.PREFIX+'/issues','POST',{})
        self.assertEqual(call.call_count,1)

    def test_pagination_totals_duplicates_and_missing_terminal_fail_closed(self):
        cases=[{'total_count':2,'jobs':[{'id':1}]},
               {'total_count':2,'jobs':[{'id':1},{'id':1}]},
               {'total_count':True,'jobs':[]}, {'total_count':0,'jobs':None}]
        for response in cases:
            with self.subTest(response=response),patch.object(b,'api',return_value=response),self.assertRaises((b.Blocked,TypeError)):
                b.pages(b.PREFIX+'/jobs','jobs')
        with patch.object(b,'api',return_value={'total_count':1,'jobs':[{'id':1}]}):
            self.assertEqual(b.pages(b.PREFIX+'/jobs','jobs'),[{'id':1}])

    def test_completion_is_counted_once_and_must_follow_recorded_request(self):
        row=dict(ordinal=1,request_id=10,state='reserved',head=HEAD,comment_id=20,
                 requested_at='2026-10-19T01:00:00Z',request_body='@codex review\nmarker',previous_completion=None)
        e=evidence();e['comments']=[dict(id=20,body=row['request_body'],user=b.ACTIONS_BOT,
            created_at=row['requested_at'],updated_at=row['requested_at'])]
        e['completed']=dict(id='completion1',head=HEAD,at='2026-10-19T01:01:00Z')
        state={'rounds':[row]}
        b.reconcile(state,e);b.reconcile(state,e)
        self.assertEqual(len(state['rounds']),1)
        self.assertEqual(row['state'],'completed')
        for update in [dict(id='other'),dict(head=BASE),dict(at='2026-10-19T01:00:00Z')]:
            bad=copy.deepcopy(e);bad['completed'].update(update)
            r=copy.deepcopy(row);r['state']='reserved'
            if update.get('id')=='other':
                with self.assertRaises(b.Blocked):b.reconcile({'rounds':[row]},bad)
            else:
                with self.assertRaises(b.Blocked):b.reconcile({'rounds':[r]},bad)

    def test_unrequested_completion_or_independent_request_blocks(self):
        e=evidence();e['completed']=dict(id='unrecorded',head=HEAD)
        with self.assertRaises(b.Blocked):b.reconcile({'rounds':[]},e)
        e=evidence();e['comments']=[dict(id=999,body='@codex review',user={'id':1,'login':'person','type':'User'})]
        with self.assertRaises(b.Blocked):b.reconcile({'rounds':[]},e)

    def test_edited_or_spoofed_request_cannot_complete(self):
        for changes in [dict(body='changed'),dict(updated_at='2026-10-19T01:00:01Z'),dict(user={'id':1})]:
            row=dict(ordinal=1,state='reserved',head=HEAD,comment_id=20,requested_at='2026-10-19T01:00:00Z',request_body='@codex review',previous_completion=None)
            e=evidence();e['completed']=dict(id='completion',head=HEAD,at='2026-10-19T01:01:00Z')
            c=dict(id=20,body=row['request_body'],user=b.ACTIONS_BOT,created_at=row['requested_at'],updated_at=row['requested_at']);c.update(changes);e['comments']=[c]
            with self.subTest(changes=changes),self.assertRaises(b.Blocked):b.reconcile({'rounds':[row]},e)

    def test_ledger_zip_requires_digest_exact_member_and_provenance(self):
        state=dict(repo=b.REPO,pr=2,run_id=100,phase='final')
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:z.writestr('ledger.json',json.dumps(state))
        raw=archive.getvalue()
        entry=dict(id=5,name='mxdr-budget-2-100-final',expired=False,workflow_run={'id':100},digest='sha256:'+b.hashlib.sha256(raw).hexdigest())
        result=type('Result',(),dict(returncode=0,stdout=raw))()
        with patch.object(b,'pages',return_value=[entry]),patch.object(b.subprocess,'run',return_value=result):
            self.assertEqual(b.artifact({'id':100},'final',2),state)
        for key,value in [('expired',True),('digest','bad'),('workflow_run',{'id':99})]:
            bad=dict(entry);bad[key]=value
            with self.subTest(key=key),patch.object(b,'pages',return_value=[bad]),patch.object(b.subprocess,'run',return_value=result),self.assertRaises(b.Blocked):b.artifact({'id':100},'final',2)

    def test_artifact_chain_cannot_reset_or_fork(self):
        run=dict(id=1,display_title='MXDR budget / PR #2',head_branch='main',event='workflow_dispatch',status='completed',conclusion='success')
        final=dict(repo=b.REPO,pr=2,run_id=1,phase='final',history=[],previous_digest=None)
        with patch.object(b.gate,'gh_api',return_value=[{'total_count':1,'workflow_runs':[run]}]),patch.object(b,'api',return_value=run),patch.object(b,'verify_run'),patch.object(b,'pages',return_value=[{'name':'mxdr-budget-2-1-final'}]),patch.object(b,'artifact',return_value=final):
            self.assertEqual(b.load_ledger(2,'main')['history'],[1])
            final['previous_digest']='missing'
            with self.assertRaises(b.Blocked):b.load_ledger(2,'main')

    def test_uncertain_write_without_final_checkpoint_blocks(self):
        run=dict(id=1,display_title='MXDR budget / PR #2',head_branch='main',event='workflow_dispatch',status='completed',conclusion='failure')
        jobs=[{'steps':[{'name':'Execute prepared action','conclusion':'failure'}]}]
        with patch.object(b.gate,'gh_api',return_value=[{'total_count':1,'workflow_runs':[run]}]),patch.object(b,'api',return_value=run),patch.object(b,'verify_run'),patch.object(b,'pages',side_effect=[[],jobs]):
            with self.assertRaises(b.Blocked):b.load_ledger(2,'main')

    def test_prepare_requests_only_new_pr_without_historical_activity(self):
        e=evidence();e['pr']['created_at']='2026-10-19T01:01:00Z'
        cfg=dict(activation_after='2026-10-19T01:00:00Z',security_review_required=True)
        with tempfile.TemporaryDirectory() as d,patch.dict(b.os.environ,{'GITHUB_RUN_ID':'10'}),patch.object(b,'config',return_value=cfg),patch.object(b,'trusted_context',return_value='main'),patch.object(b,'api',return_value={'display_title':'MXDR budget / PR #2'}),patch.object(b,'verify_run'),patch.object(b,'load_ledger',return_value=None),patch.object(b,'collect',return_value=e):
            b.prepare(2,Path(d));state=json.loads((Path(d)/'ledger.json').read_text())
            self.assertEqual(state['action'],'request');self.assertEqual(len(state['rounds']),1)
            e['summary']={'id':1}
            with self.assertRaises(b.Blocked):b.prepare(2,Path(d))

    def test_post_cap_head_change_without_p1_blocks(self):
        e=evidence()
        state=dict(rounds=[dict(state='completed',completion_id=str(i)) for i in range(3)],issues={})
        with tempfile.TemporaryDirectory() as d,patch.dict(b.os.environ,{'GITHUB_RUN_ID':'10'}),patch.object(b,'config',return_value={}),patch.object(b,'trusted_context',return_value='main'),patch.object(b,'api',return_value={'display_title':'MXDR budget / PR #2'}),patch.object(b,'verify_run'),patch.object(b,'load_ledger',return_value=state),patch.object(b,'collect',return_value=e),self.assertRaises(b.Blocked):b.prepare(2,Path(d))

    def test_act_never_posts_before_checkpoint_and_recheck(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(b.os.environ,{'GITHUB_RUN_ID':'10'}),patch.object(b,'config',return_value={}),patch.object(b,'trusted_context',return_value='main'),patch.object(b,'api') as api,patch.object(b,'verify_run'),patch.object(b,'artifact',side_effect=b.Blocked('missing')):
            with self.assertRaises(b.Blocked):b.act(2,Path(d))
            self.assertTrue(all(len(c.args)<2 or c.args[1]=='GET' for c in api.call_args_list))

    def test_budget_workflow_never_runs_pr_control_or_shares_write_test_token(self):
        from workflow_support import parse_workflow
        root=Path(__file__).resolve().parents[2]
        workflow=parse_workflow((root/'.github/workflows/review-budget.yml').read_text())
        self.assertEqual(workflow['permissions'],{})
        self.assertFalse(workflow['concurrency']['cancel-in-progress'])
        for name in ('controller','merge'):
            checkout=workflow['jobs'][name]['steps'][0]
            self.assertEqual(checkout['with'],{'ref':'${{ github.sha }}','persist-credentials':False})
        self.assertEqual(workflow['jobs']['controller']['permissions']['contents'],'read')
        self.assertEqual(workflow['jobs']['merge']['permissions']['issues'],'read')
        self.assertEqual(workflow['jobs']['merge']['permissions']['contents'],'write')
        gate=parse_workflow((root/'.github/workflows/review-clearance.yml').read_text())
        self.assertEqual(gate['permissions'],{'contents':'read'})
        self.assertNotIn('permissions',gate['jobs']['test'])
        self.assertFalse(json.loads((root/'.github/review-budget.json').read_text())['enabled'])


if __name__=='__main__':unittest.main()

class CollectionAndMergeTests(unittest.TestCase):
    def test_collector_authenticates_current_summary_and_requires_complete_threads(self):
        s={'code_review':{'status':'completed','commit_sha':HEAD,'has_any_findings':False,'has_unresolved_findings':False},
           'security_review':{'status':None,'commit_sha':None,'has_any_findings':None,'has_unresolved_findings':None}}
        summary={'id':5,'user':BOT,'body':b.gate.SUMMARY_MARKER+'\n<!-- codex-review-state:v1 '+json.dumps(s)+' -->\n| Code Review | ✅ **Completed** <relative-time datetime="2026-10-19T01:00:00Z">time</relative-time> | `'+HEAD+'` | Request |'}
        pr=dict(state='open',draft=False,mergeable=True,head={'sha':HEAD,'repo':{'full_name':b.REPO}},base={'sha':BASE,'repo':{'full_name':b.REPO}})
        def listing(path,*args,**kwargs):return [summary] if path.endswith('/comments') and '/issues/' in path else []
        with patch.object(b,'api',return_value=pr),patch.object(b,'pages',side_effect=listing),patch.object(b,'thread_evidence',return_value=([],(None,'CLEAN'))):
            e=b.collect(2,{'security_review_required':False})
            self.assertEqual(e['completed']['head'],HEAD)
            self.assertTrue(e['security_clear'])
            e=b.collect(2,{'security_review_required':True})
            self.assertFalse(e['security_clear'])
            summary['user']=dict(BOT,id=999)
            self.assertIsNone(b.collect(2,{'security_review_required':False})['completed'])

    def test_deferred_issue_receipt_is_live_readback_not_marker_only(self):
        e=evidence();state={'issues':{'key':{'number':5,'title':'Title','body':'Body','item':{'key':'key','finding_id':1}}}}
        plan=[{'key':'key','finding_id':1}]
        issue=dict(number=5,title='Title',body='Body',state='open',user=b.ACTIONS_BOT)
        with patch.object(b,'snapshot',return_value={}),patch.object(b.policy,'handoff_plan',return_value=plan),patch.object(b.policy,'clearance',return_value='ticket'),patch.object(b,'api',return_value=issue):
            self.assertEqual(b.budget_receipts(2,e,state),'ticket')
            for key,value in [('body','edited'),('state','closed'),('user',{'id':9})]:
                bad=dict(issue);bad[key]=value
                with self.subTest(key=key),patch.object(b,'api',return_value=bad),self.assertRaises(b.Blocked):b.budget_receipts(2,e,state)

    def test_merge_uses_expected_sha_and_blocks_control_changes_and_native_failure(self):
        e=evidence();e['pr'].update(changed_files=1,mergeable_state='clean')
        state=dict(head=HEAD,base=BASE,issues={},rounds=[])
        cfg=dict(native_merge_policy_verified=True,merge_queue_required=False)
        with patch.dict(b.os.environ,{'GITHUB_RUN_ID':'10','GITHUB_JOB':'merge'}),patch.object(b,'config',return_value=cfg),patch.object(b,'trusted_context',return_value='main'),patch.object(b,'api',side_effect=lambda path,method='GET',data=None: {'merged':True} if method=='PUT' else {} ) as api,patch.object(b,'verify_run'),patch.object(b,'artifact',return_value=state),patch.object(b,'collect',return_value=e),patch.object(b,'reconcile'),patch.object(b,'clean'),patch.object(b,'trusted_ci',return_value=True),patch.object(b,'pages',return_value=[{'filename':'app.py'}]) as pages:
            b.merge(2)
            writes=[c for c in api.call_args_list if len(c.args)>1 and c.args[1]=='PUT']
            self.assertEqual(writes[0].args[2],{'sha':HEAD,'merge_method':'squash'})
            api.reset_mock();pages.return_value=[{'filename':'.github/scripts/review_budget.py'}]
            with self.assertRaises(b.Blocked):b.merge(2)
            self.assertFalse(any(len(c.args)>1 and c.args[1]=='PUT' for c in api.call_args_list))
            pages.return_value=[{'filename':'app.py'}];e['merge_state']='BLOCKED'
            with self.assertRaises(b.Blocked):b.merge(2)

    def test_merge_rechecks_reviews_immediately_before_write(self):
        e=evidence();e['pr'].update(changed_files=1,mergeable_state='clean')
        fresh=copy.deepcopy(e);fresh['newer']=True
        state=dict(head=HEAD,base=BASE,issues={},rounds=[])
        cfg=dict(native_merge_policy_verified=True,merge_queue_required=False)
        with patch.dict(b.os.environ,{'GITHUB_RUN_ID':'10','GITHUB_JOB':'merge'}),patch.object(b,'config',return_value=cfg),patch.object(b,'trusted_context',return_value='main'),patch.object(b,'api') as api,patch.object(b,'verify_run'),patch.object(b,'artifact',return_value=state),patch.object(b,'collect',side_effect=[e,fresh]),patch.object(b,'reconcile'),patch.object(b,'clean'),patch.object(b,'trusted_ci',return_value=True),patch.object(b,'pages',return_value=[{'filename':'app.py'}]),self.assertRaises(b.Blocked):
            b.merge(2)
        self.assertFalse(any(len(c.args)>1 and c.args[1]=='PUT' for c in api.call_args_list))

class ActivationTests(unittest.TestCase):
    def test_existing_pr_keeps_clean_gate_after_activation(self):
        settings={'enabled':True,'activation_after':'2026-10-19T02:00:00Z'}
        with patch.object(b.gate.Path,'exists',return_value=True),patch.object(b.gate.Path,'read_text',return_value=json.dumps(settings)),patch.object(b.gate,'gh_api',return_value={'created_at':'2026-10-19T01:00:00Z'}),patch.object(b.gate,'check_clean',return_value={'clean':True}) as clean,patch.object(b,'check') as budget:
            self.assertEqual(b.gate.check(b.REPO,2),{'clean':True})
            clean.assert_called_once();budget.assert_not_called()

    def test_new_pr_cannot_choose_clean_path_to_bypass_missing_ledger(self):
        settings={'enabled':True,'activation_after':'2026-10-19T02:00:00Z'}
        with patch.object(b.gate.Path,'exists',return_value=True),patch.object(b.gate.Path,'read_text',return_value=json.dumps(settings)),patch.object(b.gate,'gh_api',return_value={'created_at':'2026-10-19T03:00:00Z'}),patch.object(b.gate,'check_clean') as clean,patch.object(b,'check',side_effect=b.Blocked('missing ledger')):
            with self.assertRaises(b.Blocked):b.gate.check(b.REPO,3)
            clean.assert_not_called()

class ReviewRegressionTests(unittest.TestCase):
    def fixture(self, level='P2'):
        from test_budget_policy import snapshot
        s = snapshot()
        finding = s['unresolved_findings'][0]
        finding['head'] = HEAD
        finding['body'] = finding['body'].replace('P2', level)
        pr = dict(state='open', draft=False, mergeable=True,
                  head={'sha': HEAD, 'repo': {'full_name': b.REPO}},
                  base={'sha': BASE, 'repo': {'full_name': b.REPO}})
        code = dict(status='completed', commit_sha=HEAD, has_any_findings=True,
                    has_unresolved_findings=True)
        security = dict(status=None, commit_sha=None, has_any_findings=None,
                        has_unresolved_findings=None)
        def summary(status='completed', head=HEAD):
            state = {'code_review': dict(code, status=status, commit_sha=head),
                     'security_review': security}
            return dict(id=5, user=BOT, body=b.gate.SUMMARY_MARKER +
                '\n<!-- codex-review-state:v1 ' + json.dumps(state) + ' -->\n' +
                '| Code Review | ✅ **Completed** <relative-time datetime="2026-10-19T01:00:00Z">time</relative-time> | `' + head + '` | Request |')
        receipt = dict(id=201, user=BOT, state='COMMENTED', commit_id=HEAD,
                       submitted_at='2026-10-19T01:00:00Z',
                       body='<!-- codex-review-receipt:v1 -->')
        inline = dict(id=101, user=BOT, pull_request_review_id=201,
                      original_commit_id=HEAD, body=finding['body'])
        threads = [dict(id='thread', isResolved=False,
                        comments={'nodes': [{'databaseId': 101}]})]
        data = {'summary': summary(), 'reactions': [], 'requests': []}
        def pages(path, *args, **kwargs):
            return {f'{b.PREFIX}/issues/2/comments': ([data['summary']] if data['summary'] else []) + data['requests'],
                    f'{b.PREFIX}/pulls/2/reviews': [receipt],
                    f'{b.PREFIX}/pulls/2/comments': [inline],
                    f'{b.PREFIX}/issues/2/reactions': data['reactions']}.get(path, [])
        state = dict(rounds=s['rounds'], issues={})
        state['rounds'][-1]['head'] = HEAD
        return pr, data, pages, threads, state, summary

    def test_live_collection_budget_clearance_rejects_running_unknown_missing_stale_and_eyes(self):
        pr, data, pages, threads, state, summary = self.fixture()
        issue = {}
        def api(path, *args, **kwargs):
            return issue if path == f'{b.PREFIX}/issues/99' else pr
        with patch.object(b, 'config', return_value={'security_review_required': False}), \
             patch.object(b, 'trusted_context', return_value='main'), \
             patch.object(b, 'load_ledger', return_value=state), \
             patch.object(b, 'api', side_effect=api), patch.object(b, 'pages', side_effect=pages), \
             patch.object(b, 'thread_evidence', return_value=(threads, (None, 'CLEAN'))):
            e = b.collect(2, {'security_review_required': False})
            state['rounds'][-1].update(completion_id=e['completed']['id'], completion=e['completed'])
            item = p.handoff_plan(b.snapshot(2, e, state))[0]
            state['issues'][item['key']] = dict(number=99, title='Title', body='Body', item=item)
            issue.update(number=99, title='Title', body='Body', state='open', user=b.ACTIONS_BOT)
            self.assertEqual(b.check(2, HEAD)['clearance_basis'], 'p2-budget')
            for label, live, reactions in [
                ('running', summary('running'), []),
                ('unknown', summary('unknown'), []),
                ('missing', None, []),
                ('stale', summary(head=BASE), []),
                ('running-eyes', summary('running'), [dict(user=BOT, content='eyes', created_at='2026-10-19T01:01:00Z')]),
                ('completed-new-eyes', summary(), [dict(user=BOT, content='eyes', created_at='2026-10-19T01:01:00Z')]),
            ]:
                data.update(summary=live, reactions=reactions)
                with self.subTest(label=label), self.assertRaises((b.Blocked, p.Blocked)):
                    b.check(2, HEAD)
            data.update(summary=summary('running'), reactions=[])
            self.assertTrue(b.collect(2, {'security_review_required': False})['newer'])
            data.update(summary=None, reactions=[dict(user=BOT, content='eyes', created_at='2026-10-19T01:01:00Z')])
            self.assertTrue(b.collect(2, {'security_review_required': False})['newer'])

    def test_third_p1_completion_persists_through_act_then_fix_head_reserves_exception(self):
        pr, data, pages, threads, state, summary = self.fixture('P1')
        data['reactions'] = [dict(user=BOT, content='eyes', created_at='2026-10-19T00:59:30Z')]
        requested = '2026-10-19T00:59:00Z'
        row = state['rounds'][-1]
        row.update(state='reserved', comment_id=20, request_body='@codex review',
                   requested_at=requested, previous_completion='completion-2')
        data['requests'] = [dict(id=20, body=row['request_body'], user=b.ACTIONS_BOT,
                                created_at=requested, updated_at=requested)]
        def api(path, *args, **kwargs):
            return {'display_title': 'MXDR budget / PR #2'} if '/actions/runs/' in path else pr
        with tempfile.TemporaryDirectory() as d, patch.dict(b.os.environ, {'GITHUB_RUN_ID': '10'}), \
             patch.object(b, 'config', return_value={'security_review_required': False}), \
             patch.object(b, 'trusted_context', return_value='main'), patch.object(b, 'verify_run'), \
             patch.object(b, 'load_ledger', side_effect=lambda *a, **kw: copy.deepcopy(state)), \
             patch.object(b, 'api', side_effect=api) as calls, patch.object(b, 'pages', side_effect=pages), \
             patch.object(b, 'thread_evidence', return_value=(threads, (None, 'CLEAN'))):
            path = Path(d) / 'ledger.json'
            b.prepare(2, Path(d))
            prepared = json.loads(path.read_text())
            self.assertEqual(prepared['rounds'][-1]['state'], 'completed')
            self.assertEqual(prepared['action'], 'none')
            self.assertIn('Only P2', prepared['clearance_blocked'])
            with patch.object(b, 'artifact', return_value=prepared):
                b.act(2, Path(d))
            state = json.loads(path.read_text())
            self.assertEqual(state['phase'], 'final')
            self.assertEqual(state['rounds'][-1]['state'], 'completed')
            self.assertFalse(any(len(c.args) > 1 and c.args[1] != 'GET' for c in calls.call_args_list))
            pr['head']['sha'] = 'e' * 40
            b.prepare(2, Path(d))
            next_state = json.loads(path.read_text())
            self.assertEqual(next_state['action'], 'request')
            self.assertEqual(len(next_state['rounds']), 4)
            self.assertEqual(sum(r['state'] == 'completed' for r in next_state['rounds']), 3)
            self.assertTrue(next_state['rounds'][-1]['p1_exception'])
            self.assertEqual(next_state['rounds'][-1]['p1_finding_id'], 101)
            self.assertEqual(next_state['rounds'][-1]['head'], 'e' * 40)

    def test_advance_controller_has_status_read_without_content_write(self):
        from workflow_support import parse_workflow
        root = Path(__file__).resolve().parents[2]
        workflow = parse_workflow((root / '.github/workflows/review-budget.yml').read_text())
        permissions = workflow['jobs']['controller']['permissions']
        self.assertEqual(permissions['statuses'], 'read')
        self.assertEqual(permissions['contents'], 'read')

    def test_trusted_ci_expects_the_actual_clearance_workflow_jobs(self):
        import base64
        from workflow_support import parse_workflow
        root = Path(__file__).resolve().parents[2]
        workflow = parse_workflow((root / '.github/workflows/review-clearance.yml').read_text())
        jobs = [dict(id=i, name=job['name'], conclusion='success')
                for i, job in enumerate(workflow['jobs'].values(), 1)]
        run = dict(id=7, path='.github/workflows/review-clearance.yml', head_branch='main',
                   event='workflow_dispatch', run_attempt=1, head_sha='c' * 40,
                   status='completed', conclusion='success')
        status = dict(id=1, context='Reviewed CI', state='success', creator=dict(b.ACTIONS_BOT),
                      target_url=f'https://github.com/{b.REPO}/actions/runs/7',
                      description=f'base:{BASE} evidence:digest')

        def api(path, method='GET', data=None):
            if '/contents/' in path:
                name = path.split('/contents/')[1].split('?')[0]
                return {'content': base64.b64encode((root / name).read_bytes()).decode()}
            return {'status': 'identical'} if '/compare/' in path else run

        with patch.object(b.gate, 'matching_runs', return_value=[run]), \
             patch.object(b, 'api', side_effect=api), \
             patch.object(b, 'pages', side_effect=lambda path, key=None: jobs if key == 'jobs' else [status]):
            self.assertTrue(b.trusted_ci(2, HEAD, BASE, 'main', 'digest'))
            next(j for j in jobs if j['name'] == workflow['jobs']['test']['name'])['conclusion'] = 'skipped'
            with self.assertRaisesRegex(b.Blocked, 'Incomplete trusted CI jobs'):
                b.trusted_ci(2, HEAD, BASE, 'main', 'digest')

class ActivationAndMergeabilityRegressionTests(unittest.TestCase):
    def configured(self):
        return dict(enabled=True, repository=b.REPO, activation_after='2026-10-19T01:00:00Z',
                    ordinary_completed_rounds=3, independent_code_triggers_disabled=True,
                    security_review_required=True, native_merge_policy_verified=True,
                    merge_queue_required=False)

    def test_partial_activation_blocks_every_phase_before_api_or_artifact(self):
        for field, invalids in [('native_merge_policy_verified', [False, None, 1, 'true']),
                                ('merge_queue_required', [True, None, 0, 'false'])]:
            for value in invalids:
                cfg = self.configured(); cfg[field] = value
                for phase in ('prepare', 'act', 'advance', 'merge'):
                    with self.subTest(field=field, value=value, phase=phase), \
                         patch.object(b.Path, 'read_text', return_value=json.dumps(cfg)), \
                         patch.object(b, 'api') as api, patch.object(b, 'trusted_context') as context, \
                         self.assertRaisesRegex(b.Blocked, 'Native merge policy'):
                        if phase in ('prepare', 'act'):
                            getattr(b, phase)(2, Path('/unused'))
                        else:
                            getattr(b, phase)(2)
                    api.assert_not_called(); context.assert_not_called()
        with patch.object(b.Path, 'read_text', return_value=json.dumps(self.configured())):
            self.assertEqual(b.config(), self.configured())

    def relay_dispatch_counts(self, configs):
        from workflow_support import parse_workflow
        root = Path(__file__).resolve().parents[2]
        script = parse_workflow((root / '.github/workflows/review-budget.yml').read_text())['jobs']['wake']['steps'][0]['with']['script']
        harness = '''const fs = require('fs'); const {script, configs} = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => { let counts = []; for (const config of configs) {
let writes = 0; const context = {repo:{owner:'nexus-kernel',repo:'CyberSOC_Creation'}, eventName:'pull_request_target',
payload:{repository:{default_branch:'main'},pull_request:{draft:false,number:2}}};
const github = {rest:{repos:{getContent:async()=>({data:{content:Buffer.from(JSON.stringify(config)).toString('base64')}})},
actions:{createWorkflowDispatch:async()=>{writes++;}}}};
await new (Object.getPrototypeOf(async function(){}).constructor)('github','context',script)(github,context);
counts.push(writes); } console.log(JSON.stringify(counts)); })().catch(e=>{console.error(e);process.exit(1);});'''
        result = b.subprocess.run(['node', '-e', harness], input=json.dumps({'script':script, 'configs':configs}),
                                  capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def test_relay_partial_activation_cannot_dispatch(self):
        configs = []
        for field, value in [('native_merge_policy_verified', False), ('native_merge_policy_verified', None),
                             ('merge_queue_required', True), ('merge_queue_required', None),
                             ('independent_code_triggers_disabled', False), ('activation_after', None)]:
            cfg = self.configured(); cfg[field] = value; configs.append(cfg)
        configs.append(self.configured())
        self.assertEqual(self.relay_dispatch_counts(configs), [0] * (len(configs)-1) + [1])

    def test_actual_relay_timestamp_contract_matches_python_config(self):
        values = [None, 123, '', '2026-10-19', '2026-10-19T01:00:00',
                  '2026-10-19 01:00:00Z', '2026-10-19T01:00:00z',
                  '2026-10-19T01:00:00Z\n', '2026-02-30T01:00:00Z',
                  '2025-02-29T01:00:00Z', '2026-10-19T24:00:00Z',
                  '2026-10-19T01:60:00Z', '2026-10-19T01:00:60Z',
                  '2026-10-19T01:00:00+24:00', '2026-10-19T01:00:00+00:60',
                  '0000-01-01T00:00:00Z', '0001-01-01T00:00:00+01:00',
                  '9999-12-31T23:59:59-01:00', '2026-00-19T01:00:00Z',
                  '2026-10-00T01:00:00Z', '2026-10-19T01:00:00Z',
                  '2024-02-29T01:00:00.123456789Z', '2000-02-29T01:00:00+23:59',
                  '2026-10-19T01:00:00-05:30', '0001-01-01T00:00:00Z',
                  '9999-12-31T23:59:59.999999Z']
        configs = [dict(self.configured(), activation_after=value) for value in values]
        dispatched = self.relay_dispatch_counts(configs)
        for value, cfg, actual in zip(values, configs, dispatched):
            with self.subTest(value=value), patch.object(b.Path, 'read_text', return_value=json.dumps(cfg)):
                try:
                    b.config()
                    expected = 1
                except (b.Blocked, b.gate.Blocked, ValueError, OverflowError):
                    expected = 0
                self.assertEqual(actual, expected)
        self.assertEqual(dispatched[3], 0)  # The reported timezone-less date must not dispatch.

    def pr(self, mergeable):
        return dict(state='open', draft=False, mergeable=mergeable,
                    head={'sha':HEAD, 'repo':{'full_name':b.REPO}},
                    base={'sha':BASE, 'repo':{'full_name':b.REPO}})

    def test_unknown_mergeability_recovers_without_writes_or_real_sleep(self):
        with patch.object(b, 'api', side_effect=[self.pr(None), self.pr(None), self.pr(True)]) as api, \
             patch.object(b.time, 'sleep') as sleep:
            self.assertTrue(b.mergeable_pr(2)['mergeable'])
            self.assertEqual([call.args for call in sleep.call_args_list], [(2,), (4,)])
            self.assertEqual(api.call_count, 3)
            self.assertTrue(all(call.args == (f'{b.PREFIX}/pulls/2',) for call in api.call_args_list))

    def test_unknown_mergeability_is_bounded_and_fails_closed(self):
        with patch.object(b, 'api', return_value=self.pr(None)) as api, \
             patch.object(b.time, 'sleep') as sleep, self.assertRaisesRegex(b.Blocked, '5 reads/30s'):
            b.mergeable_pr(2)
        self.assertEqual(api.call_count, 5)
        self.assertEqual([call.args for call in sleep.call_args_list], [(2,), (4,), (8,), (16,)])

    def test_conflicts_invalid_values_and_api_failures_are_not_retried(self):
        for value in (False, 0, 1, 'unknown'):
            with self.subTest(value=value), patch.object(b, 'api', return_value=self.pr(value)) as api, \
                 patch.object(b.time, 'sleep') as sleep, self.assertRaises(b.Blocked):
                b.mergeable_pr(2)
            self.assertEqual(api.call_count, 1); sleep.assert_not_called()
        with patch.object(b, 'api', side_effect=b.Blocked('denied')) as api, \
             patch.object(b.time, 'sleep') as sleep, self.assertRaises(b.Blocked):
            b.mergeable_pr(2)
        self.assertEqual(api.call_count, 1); sleep.assert_not_called()

    def test_retry_rejects_head_base_draft_and_closed_changes(self):
        changes = [dict(head={'sha':'e'*40, 'repo':{'full_name':b.REPO}}),
                   dict(base={'sha':'e'*40, 'repo':{'full_name':b.REPO}}),
                   dict(draft=True), dict(state='closed')]
        for change in changes:
            changed = self.pr(True); changed.update(change)
            with self.subTest(change=change), patch.object(b, 'api', side_effect=[self.pr(None), changed]) as api, \
                 patch.object(b.time, 'sleep') as sleep, self.assertRaises(b.Blocked):
                b.mergeable_pr(2)
            self.assertEqual(api.call_count, 2); sleep.assert_called_once_with(2)

    def test_actual_collect_recovers_unknown_on_initial_and_final_reads(self):
        responses = [self.pr(None), self.pr(True), self.pr(None), self.pr(True)]
        with patch.object(b, 'api', side_effect=responses) as api, patch.object(b.time, 'sleep') as sleep, \
             patch.object(b, 'pages', return_value=[]), \
             patch.object(b, 'thread_evidence', return_value=([], (None, 'CLEAN'))):
            e = b.collect(2, {'security_review_required':False})
        self.assertEqual(e['pr']['head']['sha'], HEAD)
        self.assertEqual(api.call_count, 4)
        self.assertEqual([call.args for call in sleep.call_args_list], [(2,), (2,)])
