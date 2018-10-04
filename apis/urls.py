from django.contrib.auth import views
from django.urls import include, path

app_name = 'apis'

@app.route('/api/policy/sort', methods=['POST'])
def api_policy_sort():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    data = request.form.get('data', '')
    if not data:
        return jsonify(success=False, message='no data')
    category = request.form.get('category', '')
    if category not in const.POLICY_VALID_CATEGORY:
        return jsonify(success=False, message='invalid policy category')
    rslt = db.update_policy_sort(json.loads(data), category, session.get(const.SESSION_USERNAME[0], ''))
    if rslt:
        return jsonify(success=True)
    else:
        return jsonify(success=False, message=txt.POLICY_SORT_FAIL)


@app.route('/api/policy/status/update', methods=['POST'])
def api_policy_update_status():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    _id = request.form.get('id', '')
    data = request.form.get('new_status', '')
    comment = request.form.get('comment', '')
    if not data or not _id:
        return jsonify(success=False, message='no data')
    # if data == const.POLICY_STATUS_ACTIVE.encode('utf-8'):
    #     if len(comment) < 4 or len(comment) > 256:
    #         return jsonify(success=False, message='Invalid comment message.')
    if data == const.POLICY_STATUS_ACTIVE and lib.check_setting('approve_on_active', False, session.get(const.SESSION_COMPANY[0], '')):
        rslt = db.update_policy_status(_id, const.POLICY_STATUS_APPROVE, session.get(const.SESSION_USERNAME[0], ''), comment=comment)
        if rslt:
            if not rslt.get('message', ''):
                return jsonify(success=True, message='方案保存成功，请等待管理员审批。', new_status=const.POLICY_STATUS_APPROVE)
            else:
                return jsonify(success=False, message=rslt['message'])
        else:
            return jsonify(success=False, message=txt.POLICY_UPDATE_STATUS_FAIL)
    else:
        rslt = db.update_policy_status(_id, data, session.get(const.SESSION_USERNAME[0], ''), comment=comment)
        if rslt:
            if not rslt.get('message', ''):
                return jsonify(success=True, new_status=data)
            else:
                return jsonify(success=False, message=rslt['message'])
        else:
            return jsonify(success=False, message=txt.POLICY_UPDATE_STATUS_FAIL)


@app.route('/api/policy/del', methods=['POST'])
def api_delete_policy():
    if 1 == db.delete_policy_by_id(request.form.get('id', '')):
        return jsonify(success=True)
    else:
        return jsonify(success=False, message=txt.POLICY_DEL_FAIL)


@app.route('/api/policy/design/save/<policy_id>', methods=['POST'])
def api_save_policy_design(policy_id):
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    if not check_ajax_csrf_token(request):
        return jsonify(success=False, message='Invalid token.', _csrf_token=generate_csrf_token())
    policy = db.get_policy_by_id(policy_id, session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.DATA_NOT_FOUND, _csrf_token=generate_csrf_token())
    new_design = request.form.get('design', '')
    involved_kpi = [k for k in json.loads(request.form.get('kpis', "[]"))]
    new_code = lib.design_to_py(new_design, involved_kpi)
    if not new_code.strip():
        new_code = '    pass\n'
    new_unit = request.form.get('unit', '')
    if db.update_policy_design(policy_id,
                               new_design,
                               new_code,
                               new_unit,
                               involved_kpi,
                               session.get(const.SESSION_USERNAME[0], '')).modified_count <= 1:
        return jsonify(success=True, _csrf_token=generate_csrf_token())
    else:
        return jsonify(success=False, message=txt.POLICY_UPDATE_DESIGN_FAIL, _csrf_token=generate_csrf_token())


@app.route('/api/policy/design/diff/<policy_id>', methods=['POST'])
def api_diff_policy_design(policy_id):
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    policy = db.get_policy_by_id(policy_id, session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.DATA_NOT_FOUND)
    new_design = request.form.get('design', '')
    new_code = lib.design_to_py(new_design, None)
    if not new_code.strip():
        new_code = '    pass\n'
    return jsonify(success=new_code == policy.get('code', ''))
    # return jsonify(success='\n'.join(new_design.split('\n')) == '\n'.join(policy.get('design', [])))


@app.route('/api/policy/design/check/<policy_id>', methods=['POST'])
def api_check_policy_design_syntax(policy_id):
    error_msg = ''
    func_name = '_tmp_%s' % policy_id
    design = request.form.get('design', '')
    involved_kpi = [k for k in json.loads(request.form.get('kpis', "[]"))]
    code = lib.design_to_py(design, involved_kpi)
    context = ['    kpibase = {}']
    for kpi in involved_kpi:
        code = code.replace(' %s ' % kpi, ' kpibase["%s"] ' % kpi).replace(' %s\n' % kpi, ' kpibase["%s"]\n' % kpi)
        context.append('    kpibase["%s"] = 0' % kpi)
    context = '\n'.join(context)
    code = 'def %s():\n%s\n%s\n%s()\n' % (func_name, context, code, func_name)
    try:
        exec (code)
    except Exception as e:
        error_msg = str(e)
    if error_msg:
        return jsonify(success=False, message=error_msg)
    else:
        return jsonify(success=True)


@app.route('/api/policy/results', methods=['POST'])
def api_get_policy_results():
    results = db.get_policy_results(request.form.get('id', ''), owner=session.get(const.SESSION_USERNAME[0], ''))
    if not results:
        return jsonify(success=False, message=txt.RESULT_NOT_FOUND)
    return jsonify(success=True, results=results)


@app.route('/api/calc/del', methods=['POST'])
def api_delete_calculation():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)

    calc_id = request.form.get('id', '')
    if not calc_id:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)

    if db.calc_is_used(calc_id, session.get(const.SESSION_USERNAME[0], '')):
        return jsonify(success=False, message=u'无法删除计算。该计算结果已被其他计算引用。')

    if 1 == db.delete_calc_by_id(request.form.get('id', ''), session.get(const.SESSION_USERNAME[0], '')):
        return jsonify(success=True)
    else:
        return jsonify(success=False, message=txt.CALC_DEL_FAIL)


@app.route('/api/calc/lock', methods=['POST'])
def api_lock_calculation():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)

    calc_id = request.form.get('id', '')
    if not calc_id:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)

    if 1 == db.lock_calc_by_id(request.form.get('id', ''), session.get(const.SESSION_USERNAME[0], '')):
        return jsonify(success=True)
    else:
        return jsonify(success=False, message=txt.CALC_LOCK_FAIL)


@app.route('/api/calc/unlock', methods=['POST'])
def api_unlock_calculation():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)

    calc_id = request.form.get('id', '')
    if not calc_id:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)

    if 1 == db.unlock_calc_by_id(request.form.get('id', ''), session.get(const.SESSION_USERNAME[0], '')):
        return jsonify(success=True)
    else:
        return jsonify(success=False, message=txt.CALC_UNLOCK_FAIL)


@app.route('/api/calc/status/update', methods=['POST'])
def api_update_calculation_status():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)

    calc_id = request.form.get('id', '')
    if not calc_id:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)

    new_status = request.form.get('new_status', '')
    if new_status not in ('开放计算', '待GM审批', '待VP审批', '发放'):
        return jsonify(success=False, message='Invalid status.')

    db.update_calc_status(calc_id,
                          new_status,
                          request.form.get('comment', '') if new_status == '待GM审批' else '',
                          session.get(const.SESSION_USERNAME[0], ''))
    if new_status == '待GM审批':
        return jsonify(success=True, message='申请已提交，请等待各分公司GM审批。')
    if new_status == '待VP审批':
        return jsonify(success=True, message='申请已提交，请等待VP审批。')
    else:
        return jsonify(success=True)


@app.route('/api/calc/recursion/exec', methods=['POST'])
def api_recursion_execute_calculation():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    calc_id = request.form.get('id', '')
    calc = db.get_calc_by_id(calc_id, session.get(const.SESSION_USERNAME[0], ''))
    if not calc:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)
    policy = db.get_policy_by_id(calc['policy'], session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.POLICY_NOT_FOUND)
    if not policy.get('status', '') == const.POLICY_STATUS_ACTIVE:
        return jsonify(success=False, message=u'方案《%s》状态无效：%s。请在方案进入生效状态后重试。' % (policy.get('title', ''), policy.get('status', '')))
    calc_tree = {}
    next_level_calc = [calc_id]
    while next_level_calc:
        new_next_level_calc = []
        for tmp_calc_id in next_level_calc:
            tmp_calc = db.get_calc_by_id(tmp_calc_id, session.get(const.SESSION_USERNAME[0], ''))
            if not tmp_calc:
                return jsonify(success=False, message=txt.CALC_NOT_FOUND)
            tmp_policy = db.get_policy_by_id(tmp_calc['policy'], session.get(const.SESSION_USERNAME[0], ''))
            if not tmp_policy:
                return jsonify(success=False, message=txt.POLICY_NOT_FOUND)
            if not tmp_policy.get('status', '') == const.POLICY_STATUS_ACTIVE:
                return jsonify(success=False, message=u'方案状态无效：%s。请在方案进入生效状态后重试。' % tmp_policy.get('status', ''))
            calc_tree[tmp_calc_id] = tmp_calc.get('result_source', [])
            new_next_level_calc += tmp_calc.get('result_source', [])
        next_level_calc = new_next_level_calc
    all_calc = flatten(calc_tree.values()) + calc_tree.keys()
    calc_list = []
    for i in (set(all_calc) - set(calc_tree.keys())):
        # 全部计划与有依赖的计划做差集得到没有依赖的计划
        calc_list.append(i)
    while len(calc_list) != len(set(all_calc)):
        tmp = []
        for k, v in calc_tree.items():
            if not set(v) - set(calc_list):
                tmp.append(k)
        calc_list += [i for i in (set(tmp + calc_list) - set(calc_list))]
    rslt = runTask(const.TASK_NAME_RECURSION_EXEC_CALC,
                   {const.TASK_ARG_CALCS_ID: calc_list,
                    const.TASK_ARG_OWNER: session.get(const.SESSION_USERNAME[0], ''),
                    const.TASK_ARG_DATA_DB: session.get(const.SESSION_COMPANY[0], ''),
                    const.TASK_ARG_COMPANYNAME: session.get(const.SESSION_COMPANY[0], ''),
                    const.TASK_ARG_DATA_ENV: session.get(const.SESSION_ENV[0], ''),},
                   session.get(const.SESSION_USERNAME[0], ''),
                   caller_id=calc_id)
    if rslt[0]:
        return jsonify(success=True, task_db_id=rslt[1][const.TASK_ARG_DBID], task_id=rslt[1][const.TASK_ARG_ID])
    else:
        return jsonify(success=False, message=rslt[1])



@app.route('/api/calc/exec', methods=['POST'])
def api_execute_calculation():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    calc_id = request.form.get('id', '')
    calc = db.get_calc_by_id(calc_id, session.get(const.SESSION_USERNAME[0], ''))
    if not calc:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)
    policy = db.get_policy_by_id(calc['policy'], session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.POLICY_NOT_FOUND)
    if not policy.get('status', '') == const.POLICY_STATUS_ACTIVE:
        return jsonify(success=False, message=u'方案状态无效：%s。请在方案进入生效状态后重试。' % policy.get('status', ''))
    rslt = runTask(const.TASK_NAME_EXEC_CALC,
                   {const.TASK_ARG_CALC_ID: calc_id,
                    const.TASK_ARG_DATA_DB: session.get(const.SESSION_COMPANY[0], ''),
                    const.TASK_ARG_COMPANYNAME: session.get(const.SESSION_COMPANY[0], ''),
                    const.TASK_ARG_DATA_ENV: session.get(const.SESSION_ENV[0], ''),
                    const.TASK_ARG_CALC_TITLE: '%s：%s' % (policy['title'], calc['title'])},
                   session.get(const.SESSION_USERNAME[0], ''),
                   caller_id=calc_id)
    if rslt[0]:
        return jsonify(success=True, task_db_id=rslt[1][const.TASK_ARG_DBID], task_id=rslt[1][const.TASK_ARG_ID])
    else:
        return jsonify(success=False, message=rslt[1])


@app.route('/api/tutorial/init', methods=['POST'])
def api_init_tutorial():
    rslt = runTask(const.TASK_NAME_INITTUTORIAL, {const.TASK_ARG_COMPANYNAME: cfg.APP_NAME})
    if rslt[0]:
        return jsonify(success=True, task_db_id=rslt[1][const.TASK_ARG_DBID], task_id=rslt[1][const.TASK_ARG_ID])
    else:
        return jsonify(success=False, message=rslt[1])


@app.route('/api/task/check/<task_db_id>/<task_id>/<offset>')
def api_check_task(task_db_id, task_id, offset):
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    task_is_finish = taskFinished(task_id)
    logs = []
    new_offset = offset
    rslt = db.get_task_logs(task_db_id, offset, session.get(const.SESSION_USERNAME[0], ''))
    for r in rslt:
        logs.append('%s %s' % (r['time'], r['message']))
        new_offset = r['seq']
    # print 'new offset:%s'%new_offset
    if task_is_finish:
        logs.append('<hr>')
        if taskSuccess(task_id):
            logs.append('后台任务已完成。')
        if taskFailed(task_id):
            logs.append(taskResult(task_id))
        return jsonify(success=True, logs=logs, finish=True, offset=new_offset)
    else:
        return jsonify(success=True, logs=logs, finish=False, offset=new_offset)


@app.route('/api/task/log/clear/<task_id>', methods=['POST'])
def api_clear_task_log(task_id):
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    if not check_ajax_csrf_token(request):
        return jsonify(success=False, message='Invalid token.', _csrf_token=generate_csrf_token())
    if db.clear_task_logs(task_id,
                          session.get(const.SESSION_USERNAME[0], '')).modified_count <= 1:
        return jsonify(success=True, _csrf_token=generate_csrf_token())
    else:
        return jsonify(success=False, message='清空日志失败。', _csrf_token=generate_csrf_token())


@app.route('/api/kpi/new', methods=['POST'])
def api_create_kpi():
    kpi_name = request.form.get('kpiname')
    kpi_source = request.form.get('kpisource')
    kpi_hdr = request.form.get('kpihdr')
    kpi_scope = request.form.get('kpiscope')
    if not kpi_hdr or not kpi_source or not kpi_name or not kpi_scope:
        return jsonify(success=False, message=txt.TOO_FEW_PARAMETER)
    if not kpi_source in const.VALID_KPI_SOURCE:
        return jsonify(success=False, message=txt.KPI_BAD_SOURCE)
    if not kpi_scope in const.VALID_KPI_SCOPE:
        return jsonify(success=False, message=txt.KPI_BAD_SCOPE)
    existing = db.query_kpi({'name': kpi_name, 'hdr': kpi_hdr}, 'or')
    if existing.count() > 0:
        return jsonify(success=False, message=txt.KPI_OR_HDR_EXISTING)
    rslt = db.create_kpi(kpi_name, kpi_source, kpi_hdr)
    if rslt:
        return jsonify(success=True)
    else:
        return jsonify(success=False, message=txt.KPI_CREATE_FAIL)


@app.route('/api/kpi/del', methods=['POST'])
def api_delete_kpi():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    if 1 == db.delete_kpi_by_id(request.form.get('id', ''), session.get(const.SESSION_USERNAME[0], '')):
        return jsonify(success=True)
    else:
        return jsonify(success=False, message=txt.KPI_DEL_FAIL)


@app.route('/api/results')
def api_get_results():
    resp = []
    all_rslts = db.get_results()
    for rslt in all_rslts:
        this_calc = db.get_calc_by_id(rslt['calculation'])
        if this_calc:
            this_policy = db.get_policy_by_id(this_calc['policy'], session.get(const.SESSION_USERNAME[0], ''))
            if this_policy:
                resp.append({'id': str(rslt['_id']),
                             'name': '%s:%s' % (this_policy['title'], this_calc['title']),
                             'fieldnames': db.get_result_header(rslt['_id'])})
    return jsonify(results=resp)


def _verify_jwt(uid, token):
    user = db.get_user_by_id(uid)
    if not user:
        return False, '无效的用户ID。'
    sk = user.get('secret', '')
    if not sk:
        return False, '无效的用户密钥。'
    try:
        d = jwt.decode(token, sk)
        return True, d
    except Exception as e:
        return False, str(e)


@app.route('/api/report/data')
def api_get_report_data():
    uid = request.args.get('uid', '')
    token = request.args.get('jwt', '')
    vr, vd = _verify_jwt(uid, token)
    if not vr:
        return jsonify(success=False, message=vd)
    resp = []
    policies = db.get_policy_by_category(const.POLICY_CATEGORY_REPORT, vd.get('username', ''))
    for policy in policies:
        calcs = db.get_calc_by_policy(policy['_id'], vd.get('username', ''))
        for calc in calcs:
            rslt = db.get_calc_result(calc['_id'], vd.get('username', ''), page=1)
            if rslt:
                resp.append({'id': str(rslt['_id']),
                             'name': '%s:%s' % (policy['title'], calc['title']),
                             'fieldnames': db.get_result_header(rslt['_id'], vd.get('username', ''))})
    return jsonify(success=True, results=resp)


@app.route('/api/report/data/<rslt_id>')
def api_get_report_content(rslt_id):
    uid = request.args.get('uid', '')
    token = request.args.get('jwt', '')
    vr, vd = _verify_jwt(uid, token)
    if not vr:
        return jsonify(success=False, message=vd)
    resp = {}
    rslt = db.get_result_by_id(rslt_id, vd.get('username', ''))
    if rslt:
        calc = db.get_calc_by_id(rslt['calculation'], vd.get('username', ''))
        if calc:
            policy = db.get_policy_by_id(calc['policy'], vd.get('username', ''))
            if policy:
                resp = {'name': '%s：%s' % (policy['title'], calc['title']), 'content': rslt.get('result', [])}
    return jsonify(success=True, data=resp)


@app.route('/api/report/hierarchy')
def api_get_report_hierarchy():
    uid = request.args.get('uid', '')
    token = request.args.get('jwt', '')
    vr, vd = _verify_jwt(uid, token)
    if not vr:
        return jsonify(success=False, message=vd)
    h = db.get_hierarchy(vd.get('username', '').split('@')[0].upper(), vd.get('company', ''))
    if h and '_id' in h:
        del h['_id']
        return jsonify(success=True, hierarchy=h)
    else:
        return jsonify(success=False, message='找不到架构数据。')


@app.route('/api/results/<p_title>/<c_title>')
def api_get_results_by_policy_calc_title(p_title, c_title):
    policy = db.get_policy_by_title(p_title, session.get(const.SESSION_USERNAME[0], ''))
    calc = db.get_calc_by_title(policy['_id'], c_title)
    return jsonify(results=db.get_calc_result(calc['_id'])['result'])


@app.route('/api/policy/calculation/copy', methods=['POST'])
def api_policy_calculation_quick_copy():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    # 快速复制计算中，方案并没有实际用处，验证防错误。
    policy_id = request.form.get('policy_id', '')
    policy = db.get_policy_by_id(policy_id, session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.POLICY_NOT_FOUND)
    calc_ids = json.loads(request.form.get('calc_ids', '[]'))
    # 页面上会传入不间断空格符&nbsp;，和一般空格不同，需要去掉。
    calc_titles = [str(i).replace(u'\xa0', u' ').replace(' ','') + '-副本' for i in json.loads(request.form.get('calc_titles', '[]'))]
    calc_info = {calc_ids[i]:calc_titles[i].replace(u'\xa0', u' ').replace(' ','') for i in range(max(len(calc_ids), len(calc_titles)))}
    for calc_id,new_calc_title in calc_info.items():
        if not model.valid_calc_title(new_calc_title):
            return jsonify(success=False, message=txt.BAD_CALC_TITLE_LENGTH + ":%s" % new_calc_title)
        elif db.get_calc_by_title(policy_id, new_calc_title, session.get(const.SESSION_USERNAME[0], '')):
            return jsonify(success=False, message=txt.DUPLICATED_CALC_TITLE + ":%s" % new_calc_title)
        else:
            db.copy_calculation(calc_id, new_calc_title, session.get(const.SESSION_USERNAME[0], ''))
    flash(u'计算复制成功。', 'success')
    return jsonify(success=True, title=calc_titles)

@app.route('/api/result/link', methods=['POST'])
def api_link_results():
    # policy_id = request.form.get('policy_id', '')
    # results = json.loads(request.form.get('ids', '[]'))
    # rslt, msg = db.merge_results(policy_id, '测试合并在岗月份', results)
    # if rslt:
    #   return jsonify(success=True)
    # else:
    #   return jsonify(success=False, message=msg)
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    policy = db.get_policy_by_id(request.form.get('policy_id', ''), session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.POLICY_NOT_FOUND)
    new_title = db.link_results(policy['_id'],
                                json.loads(request.form.get('calc_ids', '[]')),
                                json.loads(request.form.get('calc_titles', '[]')),
                                session.get(const.SESSION_USERNAME[0], ''))
    if not new_title:
        return jsonify(success=False, message='创建新计算失败。')
    flash(u'结果拼接成功。', 'success')
    return jsonify(success=True, title=new_title)


@app.route('/api/result/sort', methods=['POST'])
def api_sort_result():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    data = request.form.get('data', '')
    if not data:
        return jsonify(success=True, message='no data')
    policy = db.get_policy_by_id(request.form.get('policy_id', ''), session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.POLICY_NOT_FOUND)
    rslt = db.update_result_sort(policy['_id'], json.loads(data), session.get(const.SESSION_USERNAME[0], ''))
    if rslt:
        return jsonify(success=True)
    else:
        return jsonify(success=False, message=txt.RESULT_SORT_FAIL)


@app.route('/api/result/publish/search', methods=['POST'])
def api_publish_result_to_search():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    data = request.form.get('data', '')
    if not data:
        return jsonify(success=False, message='no data')
    calc_id = request.form.get('calc_id', '')
    calc = db.get_calc_by_id(calc_id, session.get(const.SESSION_USERNAME[0], ''))
    if not calc:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)
    policy = db.get_policy_by_id(calc['policy'], session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.POLICY_NOT_FOUND)
    policy_units = policy.get('unit', '').split(',')
    data = json.loads(data)
    searchable = data.get('searchable', False)
    web_index = data.get('web_index', '')
    tmp_columns = data.get('web_columns', [])
    web_columns = []
    hierarchy_version_name = data.get('hierarchy_version_name', '')
    hierarchy_version = db.get_hierarchy_version_by_name(hierarchy_version_name, session.get(const.SESSION_COMPANY[0], ''))
    hierarchy_version_id = ''
    # if not hierarchy_version:
    #     return jsonify(success=False, message=txt.HIERARCHYS_DEL_FAIL)
    if hierarchy_version:
        hierarchy_version_id = str(hierarchy_version['_id'])
    if searchable and (not web_index or web_index not in policy_units):
        return jsonify(success=False, message='保存失败：没有指定查询的身份验证字段或指定的字段不是计算单位。')
    for col in policy.get('result_columns', []):
        if col in tmp_columns and col not in web_columns:
            web_columns.append(col)
    for col in tmp_columns:
        if col not in web_columns:
            web_columns.append(col)

    rslt = ''
    if searchable:
        if not hierarchy_version:
            return jsonify(success=False, message=txt.HIERARCHY_NOT_FOUND)
    if searchable and hierarchy_version:
        rslt = db.publish_calc_result_to_search(calc['_id'],
                                                searchable,
                                                web_index,
                                                web_columns,
                                                hierarchy_version_id,
                                                session.get(const.SESSION_USERNAME[0], ''))
    elif not searchable:
        rslt = db.cancel_publish_calc_result_to_search(calc['_id'],
                                                searchable,
                                                web_index,
                                                web_columns,
                                                session.get(const.SESSION_USERNAME[0], ''))

    if rslt:
        return jsonify(success=True)
    else:
        return jsonify(success=False, message='保存失败：查询架构不可为空。')



@app.route('/api/result/publish/mobile', methods=['POST'])
def api_publish_result_to_mobile():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    data = request.form.get('data', '')
    if not data:
        return jsonify(success=False, message='no data')
    calc_id = request.form.get('calc_id', '')
    calc = db.get_calc_by_id(calc_id, session.get(const.SESSION_USERNAME[0], ''))
    if not calc:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)
    policy = db.get_policy_by_id(calc['policy'], session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.POLICY_NOT_FOUND)
    policy_units = policy.get('unit', '').split(',')
    data = json.loads(data)
    queryable = data.get('queryable', False)
    mobile_index = data.get('mobile_index', '')
    mobile_advance = data.get('mobile_advance', '').strip()
    if not mobile_advance:
        mobile_advance = {}
    try:
        mobile_advance = json.loads(mobile_advance)
        if not isinstance(mobile_advance, dict):
            mobile_advance = {}
    except Exception as jsonerror:
        return jsonify(success=False, message='公式数据格式不正确：%s' % str(jsonerror))
    tmp_columns = data.get('mobile_columns', [])
    mobile_columns = []
    if queryable and (not mobile_index or mobile_index not in policy_units):
        return jsonify(success=False, message='保存失败：没有指定对账单的身份验证字段或指定的字段不是计算单位。')
    for col in policy.get('result_columns', []):
        if col in tmp_columns and col not in mobile_columns:
            mobile_columns.append(col)
    for col in tmp_columns:
        if col not in mobile_columns:
            mobile_columns.append(col)
    rslt = db.publish_calc_result_to_query(calc['_id'],
                                           queryable,
                                           mobile_index,
                                           mobile_advance,
                                           mobile_columns,
                                           session.get(const.SESSION_USERNAME[0], ''))
    if not session.get(const.SESSION_COMPANY[0], '') == '':
        if rslt.modified_count == 1:
            tsk_rslt = runTask(const.TASK_NAME_PUBLISH_RESULT,
                               {const.TASK_ARG_CALC_ID: calc_id,
                                const.TASK_ARG_DATA_DB: session.get(const.SESSION_COMPANY[0], ''),
                                const.TASK_ARG_DATA_ENV: session.get(const.SESSION_ENV[0], ''),
                                const.TASK_ARG_CALC_TITLE: '%s：%s' % (policy['title'], calc['title'])},
                               session.get(const.SESSION_USERNAME[0], ''),
                               caller_type='Publish',
                               caller_id=calc_id)
            if tsk_rslt[0]:
                return jsonify(success=True,
                               task_db_id=tsk_rslt[1][const.TASK_ARG_DBID],
                               task_id=tsk_rslt[1][const.TASK_ARG_ID])
            else:
                return jsonify(success=False, message=tsk_rslt[1])
        else:
            return jsonify(success=False, message='保存失败：未知错误。')
    else:
        return jsonify(success=True)


@app.route('/api/result/publish', methods=['POST'])
def api_publish_result():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    data = request.form.get('data', '')
    if not data:
        return jsonify(success=False, message='no data')
    calc_id = request.form.get('calc_id', '')
    calc = db.get_calc_by_id(calc_id, session.get(const.SESSION_USERNAME[0], ''))
    if not calc:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)
    policy = db.get_policy_by_id(calc['policy'], session.get(const.SESSION_USERNAME[0], ''))
    if not policy:
        return jsonify(success=False, message=txt.POLICY_NOT_FOUND)
    policy_units = policy.get('unit', '').split(',')
    data = json.loads(data)
    queryable = data.get('queryable', False)
    mobile_index = data.get('mobile_index', '')
    mobile_advance = data.get('mobile_advance', '').strip()
    if not mobile_advance:
        mobile_advance = {}
    try:
        mobile_advance = json.loads(mobile_advance)
    except Exception as jsonerror:
        return jsonify(success=False, message='公式数据格式不正确：%s' % str(jsonerror))
    web_index = data.get('web_index', '')
    columns1 = data.get('mobile_columns', [])
    columns2 = data.get('web_columns', [])
    mobile_columns = []
    web_columns = []
    if queryable and (not mobile_index or mobile_index not in policy_units):
        return jsonify(success=False, message='保存失败：没有指定对账单的身份验证字段或指定的字段不是计算单位。')
    for col in policy.get('result_columns', []):
        if col in columns1 and col not in mobile_columns:
            mobile_columns.append(col)
        if col in columns2 and col not in web_columns:
            web_columns.append(col)
    for col in columns1:
        if col not in mobile_columns:
            mobile_columns.append(col)
    for col in columns2:
        if col not in web_columns:
            web_columns.append(col)
    rslt = db.publish_calc_result(calc['_id'],
                                  queryable,
                                  mobile_index,
                                  mobile_advance,
                                  mobile_columns,
                                  web_index,
                                  web_columns,
                                  session.get(const.SESSION_USERNAME[0], ''))
    if not session.get(const.SESSION_COMPANY[0], '') == '':
        if rslt.modified_count == 1:
            tsk_rslt = runTask(const.TASK_NAME_PUBLISH_RESULT,
                            {const.TASK_ARG_CALC_ID: calc_id,
                                const.TASK_ARG_DATA_DB: session.get(const.SESSION_COMPANY[0], ''),
                                const.TASK_ARG_DATA_ENV: session.get(const.SESSION_ENV[0], ''),
                                const.TASK_ARG_CALC_TITLE: '%s：%s' % (policy['title'], calc['title'])},
                            session.get(const.SESSION_USERNAME[0], ''),
                            caller_type='Publish',
                            caller_id=calc_id)
            if tsk_rslt[0]:
                return jsonify(success=True,
                            task_db_id=tsk_rslt[1][const.TASK_ARG_DBID],
                            task_id=tsk_rslt[1][const.TASK_ARG_ID])
            else:
                return jsonify(success=False, message=tsk_rslt[1])
        else:
            return jsonify(success=False, message='保存失败：未知错误。')
    else:
        return jsonify(success=True)


# @app.route('/api/getsecret/<username>')
# def api_get_secret(username):
#     user = db.get_user_by_username(username)
#     if user:
#         return jsonify(success=True,
#                        username=user.get('username', ''),
#                        name=user.get('real_name', ''),
#                        dbname=user.get('company', ''),
#                        key=user.get('secret', ''))
#     else:
#         return jsonify(success=False,
#                        message='无效的用户名。')

@app.route('/api/clipboard/new', methods=['POST'])
def api_add_to_clipboard():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    content = request.form.get('content', '')
    if not content or db.add_to_clipboard(content, session.get(const.SESSION_USERNAME[0], '')):
        return jsonify(success=True)
    else:
        return jsonify(success=False, message='保存到剪贴板失败。')


@app.route('/api/clipboard/paste')
def api_paste_from_clipboard():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    data = db.get_clipboard(session.get(const.SESSION_USERNAME[0], ''))
    if not data or not data[0] or not data[0].get('content', ''):
        return jsonify(success=False, message='剪贴板为空。')
    return jsonify(success=True, data=data[0].get('content', ''))


# 验证站内用户（有company、userId及secret）的JWT
@app.route('/api/verify/<uid>')
def api_verify_jwt(uid):
    user = db.get_user_by_id(uid)
    if not user:
        return jsonify(success=False, message='无效的用户ID。')
    sk = user.get('secret', '')
    if not sk:
        return jsonify(success=False, message='无效的用户密钥。')
    env = user.get('env', '')
    if env not in const.VALID_ENV:
        return jsonify(success=False, message='无效的用户环境。')
    company = db.get_company_by_name(user.get('company', ''))
    if not company:
        return jsonify(success=False, message='无效的用户Org。')
    try:
        d = jwt.decode(request.args.get('jwt', ''), sk)
        d['db_conn'] = company.get('db_conn' if env == const.ENV_PRODUCTION else 'db_conn_sandbox', {})
        d['real_name'] = user.get('real_name', '')
        return jsonify(success=True, message=d)
    except Exception as e:
        return jsonify(success=False, message=str(e))


@app.route('/api/transfer/update/<transfer_id>', methods=['POST'])
def update_transfer_status(transfer_id):
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    if not check_ajax_csrf_token(request):
        return jsonify(success=False, message='Invalid token.', _csrf_token=generate_csrf_token())
    transfer = db.get_transfer_by_id(transfer_id, session.get(const.SESSION_USERNAME[0], ''))
    if not transfer:
        return jsonify(success=False, message=txt.DATA_NOT_FOUND, _csrf_token=generate_csrf_token())
    new_status = request.form.get('status', '')
    if new_status == const.TRANSFER_STATUS_FINISHED:
        return jsonify(success=False,
                       message='Invalid status.',
                       _csrf_token=generate_csrf_token())

    m_cnt, msg = db.update_transfer_status(transfer_id,
                                           new_status,
                                           session.get(const.SESSION_USERNAME[0], ''))
    if m_cnt == 1:
        return jsonify(success=True, _csrf_token=generate_csrf_token())
    else:
        return jsonify(success=False, message=msg, _csrf_token=generate_csrf_token())


@app.route('/api/approve/update/<approve_id>', methods=['POST'])
def update_approve_status(approve_id):
    if not lib.is_im_admin(session) and not lib.is_gm(session) and not lib.is_vp(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    if not check_ajax_csrf_token(request):
        return jsonify(success=False, message='Invalid token. Please go back and retry.',
                       _csrf_token=generate_csrf_token())
    applicant = request.form.get('applicant', '')
    if not applicant:
        return jsonify(success=False, message='Invalid applicant.', _csrf_token=generate_csrf_token())
    new_status = request.form.get('status', '')
    if new_status not in const.VALID_APPROVE_STATUS + ('待VP审批', 'GM已拒绝'):
        return jsonify(success=False,
                       message='Invalid status.',
                       _csrf_token=generate_csrf_token())
    category = request.form.get('category', '')
    if category not in ('policy', 'calc'):
        return jsonify(success=False,
                       message='Invalid category.',
                       _csrf_token=generate_csrf_token())
    if new_status == const.APPROVE_STATUS_AGREED and category == 'policy':
        rslt = db.update_policy_status(approve_id, const.POLICY_STATUS_ACTIVE, applicant, force=True)
        if rslt:
            if not rslt.get('message', ''):
                pass
            else:
                return jsonify(success=False, message=rslt['message'], _csrf_token=generate_csrf_token())
        else:
            return jsonify(success=False, message=txt.POLICY_UPDATE_STATUS_FAIL, _csrf_token=generate_csrf_token())
    if new_status == '待VP审批' and category == 'calc':
        rslt = db.update_calc_status(approve_id, '待VP审批', '', applicant)
        if rslt:
            pass
        else:
            return jsonify(success=False, message='Update calculation failed.', _csrf_token=generate_csrf_token())
    if new_status == '已同意' and category == 'calc':
        rslt = db.update_calc_status(approve_id, '发放', '', applicant)
        if rslt:
            pass
        else:
            return jsonify(success=False, message='Update calculation failed.', _csrf_token=generate_csrf_token())
    if new_status == const.APPROVE_STATUS_REJECTED and category == 'policy':
        rslt = db.update_policy_status(approve_id, const.POLICY_STATUS_DESIGN, applicant, force=True)
        if rslt:
            if not rslt.get('message', ''):
                pass
            else:
                return jsonify(success=False, message=rslt['message'], _csrf_token=generate_csrf_token())
        else:
            return jsonify(success=False, message=txt.POLICY_UPDATE_STATUS_FAIL, _csrf_token=generate_csrf_token())
    if new_status in ('GM已拒绝', '已拒绝') and category == 'calc':
        rslt = db.update_calc_status(approve_id, '开放计算', '', applicant)
        if rslt:
            pass
        else:
            return jsonify(success=False, message='Update calculation failed.', _csrf_token=generate_csrf_token())
    db.update_approve_status(category,
                             approve_id,
                             new_status,
                             request.form.get('apply_time', ''),
                             request.form.get('applicant', ''),
                             session.get(const.SESSION_USERNAME[0], ''),
                             session.get(const.SESSION_COMPANY[0], ''))
    return jsonify(success=True, _csrf_token=generate_csrf_token())


@app.route('/api/get_data_header', methods=['POST'])
def api_get_data_header():
    if not lib.is_employee(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)

    data_info = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_VERSION_INFO, request.form.get('version_id', '')),
                                          session.get(const.SESSION_COMPANY[0], ''),
                                          session.get(const.SESSION_ENV[0], '')), verify=False)
    if not (data_info.status_code == 200 and data_info.json().get('success', False)):
        return jsonify(success=False, message="无法获取数据信息！")
    file_file_id = data_info.json().get('data', {}).get('file_file_id', '')
    data_request = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_HEADER, file_file_id),
                                             session.get(const.SESSION_COMPANY[0], ''),
                                             session.get(const.SESSION_ENV[0], '')))
    if not (data_request.status_code == 200 and data_request.json().get('success', False)):
        return jsonify(success=False, message='无法获取数据！')
    data_header = data_request.json().get('data', '').split(',')
    return jsonify(success=True, data={'header': data_header})


@app.route('/api/hierarchy_version/del', methods=['POST'])
def api_delete_hierarchy_version():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    if 1 == db.delete_hierarchy_version_by_id(request.form.get('id', ''), session.get(const.SESSION_COMPANY[0], '')):
        return jsonify(success=True)
    else:
        return jsonify(success=False, message=txt.HIERARCHYS_DEL_FAIL)

########################
# API For Mobile Client
########################


# 检查API Token，得到company和user id(员工号)
def _verify_mobile_token(tkn):
    try:
        # 验证通过SSO登录的用户的JWT
        d = jwt.decode(tkn, cfg.MOBILE_API_KEY)
        company_name = d.get('company', '')
        company = db.get_company_by_name(company_name)
        if not company:
            return None, None, '无效的组织名称。'
        if not d.get('user_id', ''):
            return None, None, '无效的用户ID。'
        return company_name, d['user_id'], ''
    except Exception as e:
        return None, None, str(e)


# 检查是否有架构
@app.route('/api/checkhierarchy')
def api_check_hierarchy():
    # 验证通过SSO登录的用户的JWT
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    if company_name == 'az':
        ver = db._find_one_in_org('Hierarchy', {}, company_name)
        if ver:
            ver = ver.get('version', '')
        else:
            ver = ''
        if ver and len(ver) >= 6:
            ver = '对不起，“我的奖金”使用仅适用于%s年%s月已有销售link的人员。<br>' % (ver[:4], ver[4:])
        return jsonify(success=True if db.get_hierarchy(user_id.upper(), company_name) or db.get_sim_hierarchy(user_id.upper(), company_name) else False,
                       message='%s已开放功能的销售团队包括BCBH、County及KA。<br>更多问题请拨打7575咨询。' % ver)
    elif company_name == 'hisunpfizer':
        use_tbl, use_quarter = _get_sim_source_table('', company_name)
        sql = "select * from \"%s\" where \"ntid\"='%s' limit 1" % \
              (use_tbl, user_id)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': sql})
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message='检查架构失败：%s' % r.json().get('message', '未知错误。'))
        my_data = r.json().get('data', [])
        return jsonify(success=len(my_data) > 0, data=my_data)
    elif company_name == 'bayer':
        return jsonify(success=True)
    else:
        return jsonify(success=False, message='Invalid company name.')


def _clean_az_slip_title(t):
    return t.upper().replace('BCBH&COUNTY', '').\
            replace('-BCBH', '').\
            replace('-COUNTY', '').\
            replace('BCBH', '').\
            replace('COUNTY', '').\
            replace('FOR', 'for')


# 对账单
@app.route('/api/query')
def api_query_index():
    # 验证通过SSO登录的用户的JWT
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    # Bayer直接使用系统配置的可查询方案
    if company_name == 'bayer':
        slips = db.get_queryable_calcs(company_name, uid='' if company_name == 'bayer' else user_id)
        if slips:
            return jsonify(success=True, slips=slips)
        else:
            return jsonify(success=False, message='没有可查询的奖金结果。')
    # Bayer以外的公司
    # 使用了Redis缓存
    slips = cache.get_list('%s:queryable' % company_name)
    # print len(slips)
    if not slips:
        return jsonify(success=False, message='没有可查询的奖金结果[X]。', keys=slips)
    rslt = []
    if company_name == 'mundi' or company_name == 'mundi-test':
        for slip in slips:
            this_slip = json.loads(slip)
            this_slips = cache.get_list('%s:result:%s:%s' % (company_name,
                                                             this_slip['_id'],
                                                             user_id.upper()))
            if this_slips:
                rslt.append(this_slip)
        json_response = jsonify(success=True, slips=rslt)
        json_response.headers['icpower-exception'] = 'mundi-query-form'
        return json_response
    if company_name == 'greenvalley' or company_name == 'gvtest':
        for slip in slips:
            this_slip = json.loads(slip)
            this_slips = cache.get_list('%s:result:%s:%s' % (company_name,
                                                             this_slip['_id'],
                                                             user_id.upper()))
            if this_slips:
                rslt.append(this_slip)
        return jsonify(success=True, slips=rslt)
    if company_name == 'kaniontest':
        for slip in slips:
            this_slip = json.loads(slip)
            this_slips = cache.get_list('%s:result:%s:%s' % (company_name,
                                                             this_slip['_id'],
                                                             user_id.upper()))
            if this_slips:
                rslt.append(this_slip)
        return jsonify(success=True, slips=rslt)
    if company_name == 'brightfuture':
        for slip in slips:
            this_slip = json.loads(slip)
            this_slips = cache.get_list('%s:result:%s:%s' % (company_name,
                                                             this_slip['_id'],
                                                             user_id.upper()))
            if this_slips:
                rslt.append(this_slip)
        return jsonify(success=True, slips=rslt)
    if company_name == 'xinpeng':
        for slip in slips:
            this_slip = json.loads(slip)
            this_slips = cache.get_list('%s:result:%s:%s' % (company_name,
                                                             this_slip['_id'],
                                                             user_id.upper()))
            if this_slips:
                rslt.append(this_slip)
        return jsonify(success=True, slips=rslt)
    if company_name == 'saike':
        print 'Slip query for saike employee: %s' % user_id
        sort_key = [u'员工奖金信息', u'绩效基数A明细', u'员工绩效考核得分']
        for slip in slips:
            this_slip = json.loads(slip)
            this_slips = cache.get_list('%s:result:%s:%s' % (company_name,
                                                             this_slip['_id'],
                                                             user_id.upper()))
            if this_slips:
                rslt.append(this_slip)
        # TODO 找到缓存的存入规律
        rslt.sort(key=lambda x: sort_key.index(x['title'].split('：')[0]) if x['title'].split('：')[0] in sort_key else len(sort_key)+1)
        return jsonify(success=True, slips=rslt)
    if company_name == 'cardinal':
        for slip in slips:
            this_slip = json.loads(slip)
            this_slips = cache.get_list('%s:result:%s:%s' % (company_name,
                                                             this_slip['_id'],
                                                             user_id.upper()))
            if this_slips:
                rslt.append(this_slip)
        return jsonify(success=True, slips=rslt)
    if company_name == 'uat':
        for slip in slips:
            this_slip = json.loads(slip)
            this_slips = cache.get_list('%s:result:%s:%s' % (company_name,
                                                             this_slip['_id'],
                                                             user_id.upper()))
            if this_slips:
                rslt.append(this_slip)
        return jsonify(success=True, slips=rslt)
    # az
    # need config
    # TODO 更新到17年
    RESULT_MONTH_16 = 13
    RESULT_MONTH_17 = 13
    RESULT_MONTH_18 = 5
    grp = {'2016年%d月' % (m+1): [] for m in range(RESULT_MONTH_16)}
    grp.update({'2017年%d月' % (m+1): [] for m in range(RESULT_MONTH_17)})
    grp.update({'2018年%d月' % (m+1): [] for m in range(RESULT_MONTH_18)})
    big_table = db.get_bigtable_by_user(user_id.upper(), company_name)
    if big_table:
        bt_info = {}
        for bt in big_table:
            if bt['title'] not in bt_info and bt['title'] in ('2016年3月销售代表奖金汇总',
                                                              '2016年3月地区经理奖金汇总',
                                                              '2016年Q1大区经理奖金汇总',
                                                              '2016年4月销售代表奖金汇总',
                                                              '2016年4月地区经理奖金汇总',
                                                              '2016年Q1大区经理奖金汇总v2',
                                                              '2016年5月销售代表奖金汇总',
                                                              '2016年5月地区经理奖金汇总',
                                                              '2016年Q1大区经理奖金汇总v3',
                                                              '2016年6月销售代表奖金汇总',
                                                              '2016年6月地区经理奖金汇总',
                                                              '2016年Q2大区经理奖金汇总v1',
                                                              '2016年7月销售代表奖金汇总',
                                                              '2016年7月地区经理奖金汇总',
                                                              '2016年Q2大区经理奖金汇总v2',
                                                              '2016年8月销售代表奖金汇总',
                                                              '2016年8月地区经理奖金汇总',
                                                              '2016年Q2大区经理奖金汇总v3',
                                                              '2016年9月销售代表奖金汇总',
                                                              '2016年9月地区经理奖金汇总',
                                                              '2016年Q3大区经理奖金汇总v1',
                                                              '2016年10月销售代表奖金汇总',
                                                              '2016年10月地区经理奖金汇总',
                                                              '2016年Q3大区经理奖金汇总v2',
                                                              '2016年11月销售代表奖金汇总',
                                                              '2016年11月地区经理奖金汇总',
                                                              '2016年Q3大区经理奖金汇总v3',
                                                              '2016年12月销售代表奖金汇总',
                                                              '2016年12月地区经理奖金汇总',
                                                              '2016年Q4大区经理奖金汇总v1',
                                                              '2017年01月销售代表奖金汇总',
                                                              '2017年01月地区经理奖金汇总',
                                                              '2016年Q4大区经理奖金汇总v2',
                                                              '2017年02月销售代表奖金汇总',
                                                              '2017年02月地区经理奖金汇总',
                                                              '2016年Q4大区经理奖金汇总v3',
                                                              '2017年03月销售代表奖金汇总',
                                                              '2017年03月地区经理奖金汇总',
                                                              '2017年Q1大区经理奖金汇总v1',
                                                              '2017年04月销售代表奖金汇总',
                                                              '2017年04月地区经理奖金汇总',
                                                              '2017年Q1大区经理奖金汇总v2',
                                                              '2017年05月销售代表奖金汇总',
                                                              '2017年05月地区经理奖金汇总',
                                                              '2017年Q1大区经理奖金汇总v3',
                                                              '2017年06月销售代表奖金汇总',
                                                              '2017年06月地区经理奖金汇总',
                                                              '2017年Q2大区经理奖金汇总v1',
                                                              '2017年07月销售代表奖金汇总',
                                                              '2017年07月地区经理奖金汇总',
                                                              '2017年Q2大区经理奖金汇总v2',
                                                              '2017年08月销售代表奖金汇总',
                                                              '2017年08月地区经理奖金汇总',
                                                              '2017年Q2大区经理奖金汇总v3',
                                                              '2017年09月销售代表奖金汇总',
                                                              '2017年09月地区经理奖金汇总',
                                                              '2017年Q3大区经理奖金汇总v1',
                                                              '2017年10月销售代表奖金汇总',
                                                              '2017年10月地区经理奖金汇总',
                                                              '2017年Q3大区经理奖金汇总v2',
                                                              '2017年11月销售代表奖金汇总',
                                                              '2017年11月地区经理奖金汇总',
                                                              '2017年Q3大区经理奖金汇总v3',
                                                              '2017年12月销售代表奖金汇总',
                                                              '2017年12月地区经理奖金汇总',
                                                              '2017年Q4大区经理奖金汇总v1',
                                                              '2018年01月销售代表奖金汇总',
                                                              '2018年01月地区经理奖金汇总',
                                                              '2017年Q4大区经理奖金汇总v2',
                                                              '2018年02月销售代表奖金汇总',
                                                              '2018年02月地区经理奖金汇总',
                                                              '2017年Q4大区经理奖金汇总v3',
                                                              '2018年03月销售代表奖金汇总',
                                                              '2018年03月地区经理奖金汇总',
                                                              '2018年Q1大区经理奖金汇总v1',
                                                              '2018年04月销售代表奖金汇总',
                                                              '2018年04月地区经理奖金汇总',
                                                              '2018年Q1大区经理奖金汇总v2',
                                                              '2018年05月销售代表奖金汇总',
                                                              '2018年05月地区经理奖金汇总',
                                                              '2018年Q1大区经理奖金汇总v3'
                                                              ):
                this_bt = db.get_bigtable_by_title(bt['title'], company_name)
                if this_bt:
                    bt_info[bt['title']] = {'_id': 'bt_%s' % str(this_bt['_id']),
                                            'title': bt['title']}
        for btt in bt_info:
            # TODO 更新到17年
            for m in range(RESULT_MONTH_16):
                if '2016年%d月' % (m+1) in btt:
                    grp['2016年%d月' % (m+1)].append(bt_info[btt])
            for m in range(RESULT_MONTH_17):
                if '2017年%02d月' % (m+1) in btt:
                    grp['2017年%d月' % (m+1)].append(bt_info[btt])
            for m in range(RESULT_MONTH_18):
                if '2018年%02d月' % (m+1) in btt:
                    grp['2018年%d月' % (m+1)].append(bt_info[btt])
            if btt == '2016年Q1大区经理奖金汇总':
                grp['2016年3月'].append(bt_info[btt])
            if btt == '2016年Q1大区经理奖金汇总v2':
                grp['2016年4月'].append(bt_info[btt])
            if btt == '2016年Q1大区经理奖金汇总v3':
                grp['2016年5月'].append(bt_info[btt])
            if btt == '2016年Q2大区经理奖金汇总v1':
                grp['2016年6月'].append(bt_info[btt])
            if btt == '2016年Q2大区经理奖金汇总v2':
                grp['2016年7月'].append(bt_info[btt])
            if btt == '2016年Q2大区经理奖金汇总v3':
                grp['2016年8月'].append(bt_info[btt])
            if btt == '2016年Q3大区经理奖金汇总v1':
                grp['2016年9月'].append(bt_info[btt])
            if btt == '2016年Q3大区经理奖金汇总v2':
                grp['2016年10月'].append(bt_info[btt])
            if btt == '2016年Q3大区经理奖金汇总v3':
                grp['2016年11月'].append(bt_info[btt])
            if btt == '2016年Q4大区经理奖金汇总v1':
                grp['2016年12月'].append(bt_info[btt])
            if btt == '2016年Q4大区经理奖金汇总v2':
                grp['2017年1月'].append(bt_info[btt])
            if btt == '2016年Q4大区经理奖金汇总v3':
                grp['2017年2月'].append(bt_info[btt])
            if btt == '2017年Q1大区经理奖金汇总v1':
                grp['2017年3月'].append(bt_info[btt])
            if btt == '2017年Q1大区经理奖金汇总v2':
                grp['2017年4月'].append(bt_info[btt])
            if btt == '2017年Q1大区经理奖金汇总v3':
                grp['2017年5月'].append(bt_info[btt])
            if btt == '2017年Q2大区经理奖金汇总v1':
                grp['2017年6月'].append(bt_info[btt])
            if btt == '2017年Q2大区经理奖金汇总v2':
                grp['2017年7月'].append(bt_info[btt])
            if btt == '2017年Q2大区经理奖金汇总v3':
                grp['2017年8月'].append(bt_info[btt])
            if btt == '2017年Q3大区经理奖金汇总v1':
                grp['2017年9月'].append(bt_info[btt])
            if btt == '2017年Q3大区经理奖金汇总v2':
                grp['2017年10月'].append(bt_info[btt])
            if btt == '2017年Q3大区经理奖金汇总v3':
                grp['2017年11月'].append(bt_info[btt])
            if btt == '2017年Q4大区经理奖金汇总v1':
                grp['2017年12月'].append(bt_info[btt])
            if btt == '2017年Q4大区经理奖金汇总v2':
                grp['2018年1月'].append(bt_info[btt])
            if btt == '2017年Q4大区经理奖金汇总v3':
                grp['2018年2月'].append(bt_info[btt])
            if btt == '2018年Q1大区经理奖金汇总v1':
                grp['2018年3月'].append(bt_info[btt])
            if btt == '2018年Q1大区经理奖金汇总v2':
                grp['2018年4月'].append(bt_info[btt])
            if btt == '2018年Q1大区经理奖金汇总v3':
                grp['2018年5月'].append(bt_info[btt])
    # KA团队
    # need config
    ka_table = db.get_katable_by_user(user_id.upper(), company_name)
    if ka_table:
        kt_info = {}
        for kt in ka_table:
            if kt['title'] not in kt_info and kt['title'] in ('2016年6月KA奖金',
                                                              '2016年7月KA奖金',
                                                              '2016年8月KA奖金',
                                                              '2016年9月KA奖金',
                                                              '2016年10月KA奖金',
                                                              '2016年11月KA奖金',
                                                              '2016年12月KA奖金',
                                                              '2017年01月KA奖金',
                                                              '2017年02月KA奖金',
                                                              '2017年03月KA奖金',
                                                              '2017年04月KA奖金',
                                                              '2017年05月KA奖金',
                                                              '2017年06月KA奖金',
                                                              '2017年07月KA奖金',
                                                              '2017年08月KA奖金',
                                                              '2017年09月KA奖金',
                                                              '2017年10月KA奖金',
                                                              '2017年11月KA奖金',
                                                              '2017年12月KA奖金',
                                                              '2018年01月KA奖金',
                                                              '2018年02月KA奖金',
                                                              '2018年03月KA奖金',
                                                              '2018年04月KA奖金',
                                                              '2018年05月KA奖金'
                                                             ):
                this_kt = db.get_katable_by_title(kt['title'], company_name)
                if this_kt:
                    kt_info[kt['title']] = {'_id': 'kt_%s' % str(this_kt['_id']),
                                            'title': kt['title']}
        for ktt in kt_info:
            for m in range(RESULT_MONTH_16):
                if '2016年%d月' % (m+1) in ktt:
                    grp['2016年%d月' % (m+1)].append(kt_info[ktt])
            for m in range(RESULT_MONTH_17):
                if '2017年%02d月' % (m+1) in ktt:
                    grp['2017年%d月' % (m+1)].append(kt_info[ktt])
            for m in range(RESULT_MONTH_18):
                if '2018年%02d月' % (m+1) in ktt:
                    grp['2018年%d月' % (m+1)].append(kt_info[ktt])
    checked_slip_titles = []
    from copy import deepcopy
    for slip in slips:
        this_slip = json.loads(slip)
        this_slips = cache.get_list('%s:result:%s:%s' % (company_name,
                                                         this_slip['_id'],
                                                         user_id.upper()))
        # print this_slip['title']
        # print "this is az slips:"+str(this_slip)
        if this_slips and this_slip['title'] not in checked_slip_titles:
            # print "this is no empty slip" + this_slip
            tmp_grp = deepcopy(grp)
            for m in range(RESULT_MONTH_16):
                if '2016年%d月' % (m+1) in this_slip['title']:
                    grp['2016年%d月' % (m+1)].append(this_slip)
            for m in range(RESULT_MONTH_17):
                if '2017年%d月' % (m + 1) in this_slip['title']:
                    grp['2017年%d月' % (m + 1)].append(this_slip)
            for m in range(RESULT_MONTH_18):
                if '2018年%d月' % (m + 1) in this_slip['title']:
                    grp['2018年%d月' % (m + 1)].append(this_slip)
            if this_slip['title'].endswith('2016年Q1第一次计算'):
                grp['2016年3月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q1第二次计算'):
                grp['2016年4月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q1第三次计算'):
                grp['2016年5月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q2第一次计算') or this_slip['title'].endswith('2016年Q1~Q2'):
                grp['2016年6月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q2第二次计算') or this_slip['title'].endswith('2016年Q1~Q2第二次计算') or this_slip['title'].endswith('2016年6~7月'):
                grp['2016年7月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q2第三次计算') or this_slip['title'].endswith('2016年Q1~Q2第三次计算') or this_slip['title'].endswith('2016年6~8月'):
                grp['2016年8月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q3第一次计算') or this_slip['title'].endswith('2016年6~9月'):
                grp['2016年9月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q3第二次计算') or this_slip['title'].endswith('2016年6~10月'):
                grp['2016年10月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q3第三次计算') or this_slip['title'].endswith('2016年6~11月'):
                grp['2016年11月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q4第一次计算') or this_slip['title'].endswith('2016年Q3~Q4第一次计算') or this_slip['title'].endswith('2016年6~12月'):
                grp['2016年12月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q4第二次计算') or this_slip['title'].endswith('2016年Q3~Q4第二次计算'):
                grp['2017年1月'].append(this_slip)
            if this_slip['title'].endswith('2016年Q4第三次计算') or this_slip['title'].endswith('2016年Q3~Q4第三次计算'):
                grp['2017年2月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q1第一次计算'):
                grp['2017年3月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q1第二次计算'):
                grp['2017年4月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q1第三次计算'):
                grp['2017年5月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q2第一次计算') or this_slip['title'].endswith('2017年Q1Q2第一次计算'):
                grp['2017年6月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q2第二次计算') or this_slip['title'].endswith('2017年Q1Q2第二次计算'):
                grp['2017年7月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q2第三次计算') or this_slip['title'].endswith('2017年Q1Q2第三次计算'):
                grp['2017年8月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q3第一次计算'):
                grp['2017年9月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q3第二次计算'):
                grp['2017年10月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q3第三次计算'):
                grp['2017年11月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q4第一次计算'):
                grp['2017年12月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q4第二次计算'):
                grp['2018年1月'].append(this_slip)
            if this_slip['title'].endswith('2017年Q4第三次计算'):
                grp['2018年2月'].append(this_slip)
            if this_slip['title'].endswith('2018年Q1第一次计算'):
                grp['2018年3月'].append(this_slip)
            if this_slip['title'].endswith('2018年Q1第二次计算'):
                grp['2018年4月'].append(this_slip)
            if this_slip['title'].endswith('2018年Q1第三次计算'):
                grp['2018年5月'].append(this_slip)
            if grp != tmp_grp:
                checked_slip_titles.append(this_slip['title'])
    for gp in sorted([int(gk.replace('2018年', '').replace('月', '')) for gk in grp.keys() if '2018年' in gk], reverse=True):
        for sp in grp['2018年%d月' % gp]:
            sp['year'] = '2018年%d月' % gp
            sp['title'] = _clean_az_slip_title(sp['title'])
            rslt.append(sp)
    # for gp in sorted([int(gk.replace('2017年', '').replace('月', '')) for gk in grp.keys() if '2017年' in gk], reverse=True):
    #     for sp in grp['2017年%d月' % gp]:
    #         rslt.append(sp)
    # for gp in sorted([int(gk.replace('2016年', '').replace('月', '')) for gk in grp.keys() if '2016年' in gk], reverse=True):
    #     for sp in grp['2016年%d月' % gp]:
    #         rslt.append(sp)

    uinfo = db.get_sim_hierarchy(user_id.upper(), company_name)
    if uinfo:
        my_tags = []
        if uinfo['level'].upper() == 'REP':
            # 指定模拟计算使用的原始数据。这里要让用户选择TAG，所以根据员工号搜索数据即可。
            sql = "select \"USER_CODE\",\"TAG_NAME\",\"YM\" from \"%s\" where \"USER_CODE\"='%s' and \"YM\"='201712' order by \"YM\"" % \
                (_get_sim_source_table(uinfo['team'].upper(), company_name),  # 获取使用的数据表
                uinfo.get('user_code', '').upper())
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                pass
            else:
                my_data = r.json().get('data', [])
                # need config
                for md in my_data:
                    if md['TAG_NAME']:
                        if md['TAG_NAME'] not in my_tags:
                            my_tags.append(md['TAG_NAME'])
                if 'RE-R' in my_tags:
                    tmp = []
                    for r in rslt:
                        if "12月" not in r['title']:
                            tmp.append(r)
                    rslt = tmp
    return jsonify(success=True, slips=rslt)


# 对账单详情
@app.route('/api/query/<calc_id>')
def api_query_result(calc_id):
    # 验证通过SSO登录的用户的JWT
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    # 汇总大表(只有AZ有)
    if calc_id.startswith('bt_'):
        calc = db.get_bigtable_by_id(calc_id[3:], company_name)
        if not calc:
            return jsonify(success=False, message='找不到计算或计算结果尚未开通查询。')
        slips = db._find_all_in_org('BTData',
                                    {'data.cmn.员工号': user_id.upper(), 'title': calc['title']},
                                    company_name).sort('data.display_order', pymongo.ASCENDING)
        if not slips:
            return jsonify(success=False, message='没有可查询的奖金结果。')
        display_order = []
        for ch in calc['cmn_hdr']:
            display_order.append(ch)
        for grp in calc['group_hdr']:
            for gh in calc['group_hdr'][grp]:
                display_order.append(gh['label'])
        display_order.append('当月实发总奖金')
        slips_data = []
        idx1 = 0
        idx2 = 0
        for slip in slips:
            if u'考核月份' in slip['data']['cmn'] and \
                    (u'补' in slip['data']['cmn'][u'考核月份'] or u'返' in slip['data']['cmn'][u'考核月份']) or \
                                    u'考核月' in slip['data']['cmn'] and (
                            u'补' in slip['data']['cmn'][u'考核月'] or u'返' in slip['data']['cmn'][u'考核月']):
                idx1 += 1
                this_title = '补发%s' % idx1
            else:
                idx2 += 1
                this_title = '当月%s' % idx2
            this_slip = {'title': this_title,
                         'slip': {'当月实发总奖金': slip['data']['total_pay']},
                         'display_order': display_order,
                         'formulas': []}
            for ch in calc['cmn_hdr']:
                if ch in slip['data']['cmn']:
                    this_slip['slip'][ch] = slip['data']['cmn'][ch]
            for grp in calc['group_hdr']:
                # 大横表的多个slip之间字段是有可能不同的
                if grp in slip['data']['groups']:
                    for gh in calc['group_hdr'][grp]:
                        if gh['name'] in slip['data']['groups'][grp]:
                            this_slip['slip'][gh['label']] = slip['data']['groups'][grp][gh['name']]
            slips_data.append(this_slip)
        return jsonify(success=True,
                       title=_clean_az_slip_title(calc['title']),
                       slips=slips_data,
                       related_slips=[]
                      )
    # KA汇总大表(只有AZ有)
    elif calc_id.startswith('kt_'):
        calc = db.get_katable_by_id(calc_id[3:], company_name)
        if not calc:
            return jsonify(success=False, message='找不到计算或计算结果尚未开通查询。')
        slips = db._find_all_in_org('KTData',
                                    {'data.data.员工号': user_id.upper(), 'title': calc['title']},
                                    company_name)
        if not slips:
            return jsonify(success=False, message='没有可查询的奖金结果。')
        display_order = calc['header']
        slips_data = []
        idx1 = 0
        idx2 = 0
        for slip in slips:
            if u'计算月份' in slip['data']['data'] and \
                    (u'补' in slip['data']['data'][u'计算月份'] or u'返' in slip['data']['data'][u'计算月份']) or \
                                    u'考核月份' in slip['data']['data'] and (
                            u'补' in slip['data']['data'][u'考核月份'] or u'返' in slip['data']['data'][u'考核月份']):
                idx1 += 1
                this_title = '补发%s' % idx1
            else:
                idx2 += 1
                this_title = '当月%s' % idx2
            this_slip = {'title': this_title,
                         'slip': slip['data']['data'],
                         'display_order': display_order,
                         'formulas': []}
            slips_data.append(this_slip)
        return jsonify(success=True,
                       title=_clean_az_slip_title(calc['title']),
                       slips=slips_data,
                       related_slips=[]
                      )
    # 计算结果
    else:
        if company_name == 'saike':
            defult_color = "#F9BB28" # 黄色
            color1 = "#92D050" # 绿色
            color2 = "#00B0F0" # 蓝色
            # 获取所有发布到移动端的对账单
            all_slips = []
            this_slip = cache.get_list('%s:queryable' % company_name)
            related_slips = [json.loads(s) for s in this_slip]
            slip_title = cache.get_value('%s:result.title:%s' % (company_name, calc_id), 'untitled')
            display_order = cache.get_list('%s:result.filter:%s' % (company_name, calc_id))
            slip = json.loads(cache.get_list('%s:result:%s:%s' % (company_name, calc_id, user_id.upper()))[0])
            if slip_title.startswith(u'绩效基数A明细'):
                slip = {u'详单': []}
                tmp_slips = cache.get_list('%s:result:%s:%s' % (company_name, calc_id, user_id.upper()))
                for t_slip in tmp_slips:
                    tmp_slip = json.loads(t_slip)
                    for tmp_key in tmp_slip.keys():
                        if not slip.has_key(tmp_key) and tmp_key not in [u'品规', u'销量']:
                            if tmp_key == u'本季度销量':
                                slip[u'本季度销量合计'] = slip.get(u'本季度销量合计', 0) + tmp_slip[u'本季度销量']
                            else:
                                slip[tmp_key] = tmp_slip[tmp_key]
                        elif tmp_key in [u'品规', u'销量']:
                            if tmp_key == u'销量':
                                slip[u'本季度销量合计'] = slip.get(u'本季度销量合计', 0) + tmp_slip[u'销量']
                            slip[u'详单'].append({"title": tmp_key, "value": tmp_slip[tmp_key], "color": color1})
                        elif tmp_key in [u'上季度留存量', u'本季度留存量', u'小额扣减', u'绩效基数A', u'本季度核算销量']:
                            slip[tmp_key] = slip.get(tmp_key, 0) + tmp_slip[tmp_key]
                        else:
                            pass
                display_order[display_order.index(u'销量')] = u'本季度销量合计'
                display_order[display_order.index(u'品规')] = u'详单'
            # 对部分对账单进行定制

            if slip_title.startswith(u'员工绩效考核得分'):
                # del_lables = []
                slip[u'完成率'] = u"%.2f%%" % (slip[u'完成率'] * 100)
                # if slip.get(u'考核类型') == u'完成率':
                #     slip[u'完成率'] = u"%.2f%%" % (slip[u'完成率'] * 100)
                #     del_lables = [u'环比', u'增长率', u'本季度销量', u'前4季度平均销量']
                # if slip.get(u'考核类型') == u'增长率':
                #     slip[u'环比'] = u"%.2f%%" % (slip[u'环比'] * 100)
                #     del_lables = [u'完成率', u'销量', u'任务']
                # for del_lable in del_lables:
                #     if del_lable in slip:
                #         del slip[del_lable]
                # del slip[u'考核类型']
            with open('incentivepower/conf/%s_query_color.json' % company_name, 'rb') as query_color_file:
                query_color = json.load(query_color_file)
            color = {label: defult_color for label in slip.keys()}
            for color_key in query_color.keys():
                for label in query_color[color_key]:
                    color[label] = color_key
            if slip_title.startswith(u'绩效基数A明细') and color.has_key(u'绩效基数A明细'):
                color[u'临床绩效基数'] = color2
            if slip_title.startswith(u'绩效基数A明细'):
                color[u'本季度销量合计'] = color2
            if slip_title.startswith(u'经理主管奖金信息') and color.has_key(u'扣分项'):
                color[u'扣分项'] = color1
                del slip[u'办事处/地区']
            all_slips.append({"display_order": display_order, "slip": slip, "color": color})
            return jsonify(success=True, title=slip_title, slips=all_slips, related_slips=related_slips)
        if company_name == 'cardinal':
            all_slips = []
            this_slip = cache.get_list('%s:queryable' % company_name)
            related_slips = [json.loads(s) for s in this_slip]
            slip_title = cache.get_value('%s:result.title:%s' % (company_name, calc_id), 'untitled')
            display_order = cache.get_list('%s:result.filter:%s' % (company_name, calc_id))
            slip = json.loads(cache.get_list('%s:result:%s:%s' % (company_name, calc_id, user_id.upper()))[0])
            all_slips.append({"display_order": display_order, "slip": slip})
            my_appeal = db._find_one_in_org('Appeal', {'user_id': user_id, 'calculation': calc_id}, company_name)
            if my_appeal:
                return jsonify(success=True, title=slip_title, slips=all_slips, comment=my_appeal.get('comment', ''),
                               reply=my_appeal.get('reply', ''))
            else:
                return jsonify(success=True, title=slip_title, slips=all_slips, comment='', reply='')
        if company_name == 'kaniontest':
            all_slips = []
            this_slip = cache.get_list('%s:queryable' % company_name)
            related_slips = [json.loads(s) for s in this_slip]
            slip_title = cache.get_value('%s:result.title:%s' % (company_name, calc_id), 'untitled')
            display_order = cache.get_list('%s:result.filter:%s' % (company_name, calc_id))
            slip = json.loads(cache.get_list('%s:result:%s:%s' % (company_name, calc_id, user_id.upper()))[0])
            all_slips.append({"display_order": display_order, "slip": slip})
            my_appeal = db._find_one_in_org('Appeal', {'user_id': user_id, 'calculation': calc_id}, company_name)
            if my_appeal:
                return jsonify(success=True, title=slip_title, slips=all_slips, comment=my_appeal.get('comment', ''),
                               reply=my_appeal.get('reply', ''))
            else:
                return jsonify(success=True, title=slip_title, slips=all_slips, comment='', reply='')
        if company_name == 'bayer':
            my_slip = db.get_slip(company_name, user_id, calc_id)
            if my_slip and my_slip['result']:
                slips = []
                for sr in my_slip['result']:
                    slips.append({'display_order': my_slip['display_order'], 'slip': {k: str(sr[k]) for k in my_slip['display_order']}})
                my_appeal = db._find_one_in_org('Appeal', {'user_id': user_id, 'calculation': calc_id}, company_name)
                if my_appeal:
                    return jsonify(success=True, title=my_slip['title'], slips=slips, comment=my_appeal.get('comment', ''), reply=my_appeal.get('reply', ''))
                else:
                    return jsonify(success=True, title=my_slip['title'], slips=slips, comment='', reply='')
            else:
                return jsonify(success=False, message='对不起，该计算结果中没有查询到您的数据。')
        if company_name =='brightfuture':
            my_slip = db.get_slip(company_name, user_id, calc_id)
            if my_slip and my_slip['result']:
                slips = []
                # if u'岗位编码' in my_slip['display_order']:
                #     my_slip['display_order'].remove(u'岗位编码')
                for sr in my_slip['result']:
                    # try:
                    #     slips.append({'display_order': my_slip['display_order'],
                    #                   'slip': {k: format(int(sr[k]), ',') for k in my_slip['display_order']}})
                    # except ValueError:
                    #     slips.append({'display_order': my_slip['display_order'],
                    #                   'slip': {k: str(sr[k]) for k in my_slip['display_order']}})
                    slips.append({'display_order': my_slip['display_order'],
                                  'slip': {k: str(sr[k]) if not type(sr[k]) in (int, float, long) else format(sr[k], ',') for k in my_slip['display_order']}})
                my_appeal = db._find_one_in_org('Appeal', {'user_id': user_id, 'calculation': calc_id},
                                                company_name)
                if my_appeal:
                    return jsonify(success=True, title=my_slip['title'], slips=slips,
                                   comment=my_appeal.get('comment', ''), reply=my_appeal.get('reply', ''))
                else:
                    return jsonify(success=True, title=my_slip['title'], slips=slips, comment='', reply='')
            else:
                return jsonify(success=False, message='对不起，该计算结果中没有查询到您的数据。')
        if company_name =='greenvalley' or company_name == 'gvtest':
            my_slip = db.get_slip(company_name, user_id, calc_id)
            if my_slip and my_slip['result']:
                slips = []
                slip_title = cache.get_value('%s:result.title:%s' % (company_name, calc_id), 'untitled')
                # if u'岗位编码' in my_slip['display_order']:
                #     my_slip['display_order'].remove(u'岗位编码')
                for sr in my_slip['result']:
                    # try:
                    #     slips.append({'display_order': my_slip['display_order'],
                    #                   'slip': {k: format(int(sr[k]), ',') for k in my_slip['display_order']}})
                    # except ValueError:
                    #     slips.append({'display_order': my_slip['display_order'],
                    #                   'slip': {k: str(sr[k]) for k in my_slip['display_order']}})
                    formulas = {
                        u"自营-医学信息沟通专员": u"岗位季度达成奖 =<br>(季度销量 × 单支奖金)<br>× 达成系数",
                        u"自营-医学信息沟通专员(县域)": u"岗位季度达成奖 =<br>(季度销量 × 单支奖金)<br>× 达成系数",
                        u"自营-区域经理": u"岗位季度达成奖 =<br>(季度销量 × 单支奖金)<br>× 达成系数 + 连续达成奖",
                        u"招商福建经理/主管": u"岗位季度达成奖 =<br>当季度纯销销量 × 单支奖金",
                        u"招商经理/主管": u"岗位季度达成奖 =<br>(当季度纯销销量 × 单支奖金)<br>× 达成系数 × 增长系数<br>+ 连续达成奖",
                        u"民营&招商-大区(副)经理": u"岗位季度达成奖 =<br>(下属岗位达成奖总和<br>/ 下属岗位数 × P)<br>× 打折系数<br>+ (民营纯销销量 × 单支奖金)<br>+ 连续达成奖",
                        u"民营-终端招商经理": u"岗位季度达成奖 =<br>当季度纯销销量 × 单支奖金",
                        u"自营-大区经理": u"岗位季度达成奖 =<br>下属岗位达成奖总和 / 下属岗位数<br>× P <br> + 连续达成奖",
                        u"销售总监": u"岗位季度达成奖 =<br>奖金基数<br>× (当季度纯销销量<br>/ 当季度纯销指标)",
                        u"招商-李毅": u"岗位季度达成奖 =<br>非民营招商奖金+民营奖金=<br>(当季度非民营纯销销量<br>× 单支奖金 × 达成系数<br>× 增长系数 × 打折系数<br>+ 当季度民营纯销销量<br> × 单支奖金)<br> + 连续达成奖",
                        u"伟素-总监": u"岗位季度达成奖 =<br>季度发货量 / 季度发货指标<br>× 奖金基数",
                        u"伟素-大区经理": u"岗位季度达成奖 =<br>季度纯销销量 × 单支提成奖金",
                        u"伟素-省区&销售": u"岗位季度达成奖 =<br>季度纯销销量 × 单支提成奖金",
                        u"伟素-副总监": u"岗位季度达成奖 =<br>季度纯销销量 / 季度纯销指标<br>× 奖金基数"
                    }
                    display_order = my_slip['display_order']
                    slip = {k: str(sr[k]) if not type(sr[k]) in (int, float, long) else format(sr[k], ',') for k in my_slip['display_order']}
                    for title in formulas:
                        if title in my_slip['title'] and app.debug:
                            display_order.append(u'公式')
                            slip[u'公式'] = formulas[title]
                            break

                    slips.append({'display_order': display_order, 'slip': slip})
                my_appeal = db._find_one_in_org('Appeal', {'user_id': user_id, 'calculation': calc_id},
                                                company_name)
                confirm_result = db.get_calc_confirm_in_org_by_info(user_id, calc_id, company_name)
                confirmed = True if confirm_result else False
                if my_appeal:
                    return jsonify(success=True, title=my_slip['title'], slips=slips, confirmed=confirmed,
                                   comment=my_appeal.get('comment', ''), reply=my_appeal.get('reply', ''))
                else:
                    return jsonify(success=True, title=my_slip['title'], slips=slips,
                                   comment='', reply='', confirmed=confirmed,)
            else:
                return jsonify(success=False, message='对不起，该计算结果中没有查询到您的数据。')
        if company_name =='xinpeng':
            my_slip = db.get_slip(company_name, user_id, calc_id)
            if my_slip and my_slip['result']:
                slips = []
                # if u'岗位编码' in my_slip['display_order']:
                #     my_slip['display_order'].remove(u'岗位编码')
                for sr in my_slip['result']:
                    # try:
                    #     slips.append({'display_order': my_slip['display_order'],
                    #                   'slip': {k: format(int(sr[k]), ',') for k in my_slip['display_order']}})
                    # except ValueError:
                    #     slips.append({'display_order': my_slip['display_order'],
                    #                   'slip': {k: str(sr[k]) for k in my_slip['display_order']}})
                    slips.append({'display_order': my_slip['display_order'],
                                  'slip': {k: str(sr[k]) if not type(sr[k]) in (int, float, long) else format(sr[k], ',') for k in my_slip['display_order']}})
                my_appeal = db._find_one_in_org('Appeal', {'user_id': user_id, 'calculation': calc_id},
                                                company_name)
                if my_appeal:
                    return jsonify(success=True, title=my_slip['title'], slips=slips,
                                   comment=my_appeal.get('comment', ''), reply=my_appeal.get('reply', ''))
                else:
                    return jsonify(success=True, title=my_slip['title'], slips=slips, comment='', reply='')
            else:
                return jsonify(success=False, message='对不起，该计算结果中没有查询到您的数据。')
        if company_name in ['mundi', 'mundi-test']:
            my_slip = db.get_slip(company_name, user_id, calc_id)
            if my_slip and my_slip['result']:
                slips = []
                for sr in my_slip['result']:
                    slips.append({'display_order': my_slip['display_order'], 'slip': {k: str(sr[k]) for k in my_slip['display_order']}})
                my_appeal = db._find_one_in_org('Appeal', {'user_id': user_id, 'calculation': calc_id}, company_name)
                if my_appeal:
                    json_response = jsonify(success=True, title=my_slip['title'], slips=slips, comment=my_appeal.get('comment', ''), reply=my_appeal.get('reply', ''))
                else:
                    json_response = jsonify(success=True, title=my_slip['title'], slips=slips, comment='', reply='')
            else:
                json_response = jsonify(success=False, message='对不起，该计算结果中没有查询到您的数据。')
            json_response.headers['icpower-exception'] = 'mundi-query-form'
            return json_response
        if company_name == 'uat':
            all_slips = []
            this_slip = cache.get_list('%s:queryable' % company_name)
            related_slips = [json.loads(s) for s in this_slip]
            slip_title = cache.get_value('%s:result.title:%s' % (company_name, calc_id), 'untitled')
            display_order = cache.get_list('%s:result.filter:%s' % (company_name, calc_id))
            slip = json.loads(cache.get_list('%s:result:%s:%s' % (company_name, calc_id, user_id.upper()))[0])
            all_slips.append({"display_order": display_order, "slip": slip})
            my_appeal = db._find_one_in_org('Appeal', {'user_id': user_id, 'calculation': calc_id}, company_name)
            if my_appeal:
                return jsonify(success=True, title=slip_title, slips=all_slips, comment=my_appeal.get('comment', ''),
                               reply=my_appeal.get('reply', ''))
            else:
                return jsonify(success=True, title=slip_title, slips=all_slips, comment='', reply='')
        # az
        calc = db.get_calc_in_org(calc_id, company_name)
        if not calc or not calc.get('queryable', False):
            return jsonify(success=False, message='找不到计算或计算结果尚未开通查询。')
        slips = cache.get_list('%s:result:%s:%s' % (company_name, calc_id, user_id.upper()))
        if not slips:
            return jsonify(success=False, message='没有可查询的奖金结果。')
        display_order = cache.get_list('%s:result.filter:%s' % (company_name, calc_id))
        slip_title = cache.get_value('%s:result.title:%s' % (company_name, calc_id), 'untitled')
        formulas = calc.get('mobile_advance', {}).get('formulas', [])
        final_slips = [json.loads(slip) for slip in slips]
        if company_name == 'az':
            user_id = user_id.upper()
            all_slips = []
            if slip_title.startswith('2016年County大区经理销售绩效奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': display_order,
                                 'formulas': [{'title': 'YTD达成奖',
                                               'formula': '||达成奖|| = ||达成奖基数|| * ||产品A/T系数|| * ||策略系数|| * ||在岗月份数|| * ||AS系数||'}]
                                }
                    if fslip[u'产品达成率'] < 0.6:
                        this_slip['formulas'] += [{'title': '因为产品达成率 < 60%',
                                                   'formula': 'YTD达成奖 = 0',
                                                   'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2016年BCBH大区经理达成奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': display_order,
                                 'formulas': [{'title': 'YTD达成奖',
                                               'formula': '||达成奖|| = ||达成奖基数|| * ||在岗月份数|| * '}]
                                }
                    if fslip['TA1 A/T'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||TA1 A/T系数|| * ||TA1权重||'
                    else:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||0||'
                    if fslip['TA2 A/T'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += ' + ||TA2 A/T系数|| * ||TA2权重||'
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0||'
                    if fslip['TA3 A/T'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += ' + ||TA3 A/T系数|| * ||TA3权重|| ||)||'
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0|| ||)||'
                    if fslip[u'全产品A/T'] < 0.8:
                        this_slip['formulas'] += [{'title': '因为全产品A/T < 80%',
                                                   'formula': 'YTD达成奖 = 0',
                                                   'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2017年BCBH大区经理达成奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': display_order,
                                 'formulas': [{'title': 'YTD达成奖',
                                               'formula': '||达成奖|| = ||达成奖基数|| * ||在岗月份数|| * '}]
                                }
                    if fslip['TA1 A/T'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||TA1 A/T系数|| * ||TA1权重||'
                    else:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||0||'
                    if fslip['TA2 A/T'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += ' + ||TA2 A/T系数|| * ||TA2权重||'
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0||'
                    if fslip['TA3 A/T'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += ' + ||TA3 A/T系数|| * ||TA3权重|| ||)||'
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0|| ||)||'
                    if fslip[u'全产品A/T'] < 0.8:
                        this_slip['formulas'] += [{'title': '因为全产品A/T < 80%',
                                                   'formula': 'YTD达成奖 = 0',
                                                   'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2017年BCBH&County地区经理销售绩效奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    if '2017年1月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年2月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| + ||2月代表达成贡献奖总和|| / ||2月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| + ||2月代表增长奖总和|| / ||2月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年3月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| + ||2月代表达成贡献奖总和|| / ||2月代表在岗人数|| + ||3月代表达成贡献奖总和|| / ||3月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| + ||2月代表增长奖总和|| / ||2月代表在岗人数|| + ||3月代表增长奖总和|| / ||3月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年4月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| + ||2月代表达成贡献奖总和|| / ||2月代表在岗人数|| + ||3月代表达成贡献奖总和|| / ||3月代表在岗人数|| + ||4月代表达成贡献奖总和|| / ||4月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| + ||2月代表增长奖总和|| / ||2月代表在岗人数|| + ||3月代表增长奖总和|| / ||3月代表在岗人数|| + ||4月代表增长奖总和|| / ||4月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年5月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| + ||2月代表达成贡献奖总和|| / ||2月代表在岗人数|| + ||3月代表达成贡献奖总和|| / ||3月代表在岗人数|| + ||4月代表达成贡献奖总和|| / ||4月代表在岗人数|| + ||5月代表达成贡献奖总和|| / ||5月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| + ||2月代表增长奖总和|| / ||2月代表在岗人数|| + ||3月代表增长奖总和|| / ||3月代表在岗人数|| + ||4月代表增长奖总和|| / ||4月代表在岗人数|| + ||5月代表增长奖总和|| / ||5月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年6月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| + ||2月代表达成贡献奖总和|| / ||2月代表在岗人数|| + ||3月代表达成贡献奖总和|| / ||3月代表在岗人数|| + ||4月代表达成贡献奖总和|| / ||4月代表在岗人数|| + ||5月代表达成贡献奖总和|| / ||5月代表在岗人数|| + ||6月代表达成贡献奖总和|| / ||6月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| + ||2月代表增长奖总和|| / ||2月代表在岗人数|| + ||3月代表增长奖总和|| / ||3月代表在岗人数|| + ||4月代表增长奖总和|| / ||4月代表在岗人数|| + ||5月代表增长奖总和|| / ||5月代表在岗人数|| + ||6月代表增长奖总和|| / ||6月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年7月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年8月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年9月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| + ||9月代表达成贡献奖总和|| / ||9月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| + ||9月代表增长奖总和|| / ||9月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年10月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| + ||9月代表达成贡献奖总和|| / ||9月代表在岗人数|| + ||10月代表达成贡献奖总和|| / ||10月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| + ||9月代表增长奖总和|| / ||9月代表在岗人数|| + ||10月代表增长奖总和|| / ||10月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年11月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| + ||9月代表达成贡献奖总和|| / ||9月代表在岗人数|| + ||10月代表达成贡献奖总和|| / ||10月代表在岗人数|| + ||11月代表达成贡献奖总和|| / ||11月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| + ||9月代表增长奖总和|| / ||9月代表在岗人数|| + ||10月代表增长奖总和|| / ||10月代表在岗人数|| + ||11月代表增长奖总和|| / ||11月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2017年12月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| + ||9月代表达成贡献奖总和|| / ||9月代表在岗人数|| + ||10月代表达成贡献奖总和|| / ||10月代表在岗人数|| + ||11月代表达成贡献奖总和|| / ||11月代表在岗人数|| + ||12月代表达成贡献奖总和|| / ||12月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| + ||9月代表增长奖总和|| / ||9月代表在岗人数|| + ||10月代表增长奖总和|| / ||10月代表在岗人数|| + ||11月代表增长奖总和|| / ||11月代表在岗人数|| + ||12月代表增长奖总和|| / ||12月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    else:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    if fslip['TAG'] in ('CVB', 'DMO', 'RE3', 'BCA', 'BCAF', 'BCF', 'BCZ', 'OCMIX_C', 'OCMIX_E',
                                        'PBG_C', 'PBG_E', 'LCI', 'LCI_1', 'LCI_2'):
                        if fslip[u'全产品A/T'] < 0.6:
                            this_slip['formulas'] += [{'title': '因为全产品A/T < 60%',
                                                       'formula': 'YTD达成奖 = 0' if '2017年1月' in slip_title else 'YTD达成奖 = 0<br>YTD增长奖 = 0',
                                                       'raw': True}]
                    else:
                        if fslip[u'全产品A/T'] < 0.8:
                            this_slip['formulas'] += [{'title': '因为全产品A/T < 80%',
                                                       'formula': 'YTD达成奖 = 0' if '2017年1月' in slip_title else 'YTD达成奖 = 0<br>YTD增长奖 = 0',
                                                       'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2016年BCBH&County地区经理销售绩效奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    if '2016年12月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| + ||9月代表达成贡献奖总和|| / ||9月代表在岗人数|| + ||10月代表达成贡献奖总和|| / ||10月代表在岗人数|| + ||11月代表达成贡献奖总和|| / ||11月代表在岗人数|| + ||12月代表达成贡献奖总和|| / ||12月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| + ||9月代表增长奖总和|| / ||9月代表在岗人数|| + ||10月代表增长奖总和|| / ||10月代表在岗人数|| + ||11月代表增长奖总和|| / ||11月代表在岗人数|| + ||12月代表增长奖总和|| / ||12月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2016年11月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| + ||9月代表达成贡献奖总和|| / ||9月代表在岗人数|| + ||10月代表达成贡献奖总和|| / ||10月代表在岗人数|| + ||11月代表达成贡献奖总和|| / ||11月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| + ||9月代表增长奖总和|| / ||9月代表在岗人数|| + ||10月代表增长奖总和|| / ||10月代表在岗人数|| + ||11月代表增长奖总和|| / ||11月代表在岗人数|| ||)|| * ||1.4||'}]
                                    }
                    elif '2016年10月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| + ||9月代表达成贡献奖总和|| / ||9月代表在岗人数|| + ||10月代表达成贡献奖总和|| / ||10月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| + ||9月代表增长奖总和|| / ||9月代表在岗人数|| + ||10月代表增长奖总和|| / ||10月代表在岗人数|| ||)|| * ||1.4||'}]
                                    }
                    elif '2016年9月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| + ||9月代表达成贡献奖总和|| / ||9月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| + ||9月代表增长奖总和|| / ||9月代表在岗人数|| ||)|| * ||1.4||'}]
                                    }
                    elif '2016年8月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| + ||8月代表达成贡献奖总和|| / ||8月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| + ||8月代表增长奖总和|| / ||8月代表在岗人数|| ||)|| * ||1.4||'}]
                                    }
                    elif '2016年7月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||7月代表达成贡献奖总和|| / ||7月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||7月代表增长奖总和|| / ||7月代表在岗人数|| ||)|| * ||1.4||'}]
                                    }
                    elif '2016年6月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| + ||2月代表达成贡献奖总和|| / ||2月代表在岗人数|| + ||3月代表达成贡献奖总和|| / ||3月代表在岗人数|| + ||4月代表达成贡献奖总和|| / ||4月代表在岗人数|| + ||5月代表达成贡献奖总和|| / ||5月代表在岗人数|| + ||6月代表达成贡献奖总和|| / ||6月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| + ||2月代表增长奖总和|| / ||2月代表在岗人数|| + ||3月代表增长奖总和|| / ||3月代表在岗人数|| + ||4月代表增长奖总和|| / ||4月代表在岗人数|| + ||5月代表增长奖总和|| / ||5月代表在岗人数|| + ||6月代表增长奖总和|| / ||6月代表在岗人数|| ||)|| * ||1.4||'}]
                                    }
                    elif '2016年5月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| + ||2月代表达成贡献奖总和|| / ||2月代表在岗人数|| + ||3月代表达成贡献奖总和|| / ||3月代表在岗人数|| + ||4月代表达成贡献奖总和|| / ||4月代表在岗人数|| + ||5月代表达成贡献奖总和|| / ||5月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| + ||2月代表增长奖总和|| / ||2月代表在岗人数|| + ||3月代表增长奖总和|| / ||3月代表在岗人数|| + ||4月代表增长奖总和|| / ||4月代表在岗人数|| + ||5月代表增长奖总和|| / ||5月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    elif '2016年4月' in slip_title:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| + ||2月代表达成贡献奖总和|| / ||2月代表在岗人数|| + ||3月代表达成贡献奖总和|| / ||3月代表在岗人数|| + ||4月代表达成贡献奖总和|| / ||4月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| + ||2月代表增长奖总和|| / ||2月代表在岗人数|| + ||3月代表增长奖总和|| / ||3月代表在岗人数|| + ||4月代表增长奖总和|| / ||4月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    else:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'YTD达成奖',
                                                   'formula': '||达成贡献奖|| = ||(|| ||1月代表达成贡献奖总和|| / ||1月代表在岗人数|| + ||2月代表达成贡献奖总和|| / ||2月代表在岗人数|| + ||3月代表达成贡献奖总和|| / ||3月代表在岗人数|| ||)|| * ||1.4||'},
                                                  {'title': 'YTD增长奖',
                                                   'formula': '||增长奖|| = ||(|| ||1月代表增长奖总和|| / ||1月代表在岗人数|| + ||2月代表增长奖总和|| / ||2月代表在岗人数|| + ||3月代表增长奖总和|| / ||3月代表在岗人数|| ||)|| * ||1.4||'}]
                                     }
                    if fslip['TAG'] in ('CVB', 'DMO', 'DMB', 'DMX', 'BCF', 'CT'):
                        if fslip[u'全产品A/T'] < 0.6:
                            this_slip['formulas'] += [{'title': '因为全产品A/T < 60%',
                                                       'formula': 'YTD达成奖 = 0' if '2016年7月' in slip_title or '2016年8月' in slip_title or '2016年9月' or '2016年10月' or '2016年11月' or '2016年12月' in slip_title else 'YTD达成奖 = 0<br>YTD增长奖 = 0',
                                                       'raw': True}]
                    else:
                        if fslip[u'全产品A/T'] < 0.8:
                            this_slip['formulas'] += [{'title': '因为全产品A/T < 80%',
                                                       'formula': 'YTD达成奖 = 0' if '2016年7月' in slip_title or '2016年8月' in slip_title or '2016年9月' or '2016年10月' or '2016年11月' or '2016年12月' in slip_title else 'YTD达成奖 = 0<br>YTD增长奖 = 0',
                                                       'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2017年County代表销售绩效奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': display_order,
                                 'formulas': [{'title': 'YTD达成奖',
                                               'formula': '||达成贡献奖|| = ||奖金基数|| * ||在岗月份数|| * ||贡献率系数|| * ||(|| ||RIA-A/T系数|| * ||RIA奖金权重|| + ||CVM+GI-A/T系数|| * ||CVM+GI奖金权重|| + ||Onco-A/T系数|| * ||Onco奖金权重|| ||)||'},
                                              {'title': 'YTD增长奖',
                                               'formula': '||标准增长奖金|| = ||RIA净增长金额|| * ||RIA增长系数|| + ||GI净增长金额|| * ||GI增长系数|| + ||CVM净增长金额|| * ||CVM增长系数|| + ||Once净增长金额|| * ||Once增长系数||' if 'H2' not in slip_title \
                                                   else '||标准增长奖金|| = ||RIA净增长金额|| * ||RIA增长系数|| + ||GI净增长金额|| * ||GI增长系数|| + ||CVM净增长金额|| * ||CVM增长系数|| + ||Once净增长金额|| * ||Once增长系数|| + ||Tagrisso净增长金额|| * ||Tagrisso增长系数||'}]
                                 }
                    if fslip[u'产品达成率'] < 0.6:
                        this_slip['formulas'] += [{'title': '因为产品达成率 < 60%',
                                                   'formula': 'YTD达成奖 = 0<br>YTD增长奖 = 0',
                                                   'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2016_County_MR_销售绩效奖') or slip_title.startswith('2016年County代表销售绩效奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': display_order,
                                 'formulas': [{'title': 'YTD达成奖',
                                               'formula': '||达成奖|| = ||达成奖基数|| * ||产品A/T系数|| * ||策略系数|| * ||在岗月份数|| * ||AS系数||'},
                                              {'title': 'YTD增长奖',
                                               'formula': '||增长奖|| = ||(|| ||产品销量|| - ||产品去年销量|| ||)|| * ||增长系数|| * ||策略系数|| * ||AS系数||'}]
                                 }
                    if fslip[u'产品达成率'] < 0.6:
                        this_slip['formulas'] += [{'title': '因为产品达成率 < 60%',
                                                   'formula': 'YTD达成奖 = 0<br>YTD增长奖 = 0',
                                                   'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2017年BCBH代表达成贡献奖'):

                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': display_order,
                                 'formulas': [{'title': 'YTD达成贡献奖',
                                               'formula': '||达成贡献奖|| = ||奖金基数|| * ||在岗月份数|| * ||贡献率系数|| * '}]}
                    # CVB不考核人均生产力
                    if this_slip['slip'][u'TAG标准人均生产力'] == -1:
                        this_slip['slip'][u'TAG标准人均生产力'] = '-'
                    # 起奖线 OCMIX与BCAZ为H2 TAGS
                    if (fslip['TAG'] in ('CVB', 'DMO', 'RE3', 'BCA', 'BCAF', 'BCF', 'BCZ', 'BCAZ', 'OCMIX_C', 'OCMIX',
                                         'OCMIX_E', 'PBG_C', 'PBG_E', 'LCI', 'LCI_1', 'LCI_2'
                                         )) and fslip[u'产品1达成率'] >= 0.6 or fslip[u'产品1达成率'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||产品1A/T系数|| * ||产品1奖金权重||'
                    else:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||0||'
                    if (fslip['TAG'] in ('CVB', 'DMO', 'RE3', 'BCA', 'BCAF', 'BCF', 'BCZ', 'BCAZ', 'OCMIX_C', 'OCMIX',
                                         'OCMIX_E', 'PBG_C', 'PBG_E', 'LCI', 'LCI_1', 'LCI_2'
                                         )) and fslip[u'产品2达成率'] >= 0.6 or fslip[u'产品2达成率'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += ' + ||产品2A/T系数|| * ||产品2奖金权重||'
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0||'
                    if (fslip['TAG'] in ('CVB', 'DMO', 'RE3', 'BCA', 'BCAF', 'BCF', 'BCZ', 'BCAZ', 'OCMIX_C', 'OCMIX',
                                         'OCMIX_E', 'PBG_C', 'PBG_E', 'LCI', 'LCI_1', 'LCI_2'
                                         )) and fslip[u'产品3达成率'] >= 0.6 or fslip[u'产品3达成率'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += ' + ||产品3A/T系数|| * ||产品3奖金权重|| ||)||'
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0|| ||)||'
                    # 策略产品
                    if 'H2' in slip_title:
                        if fslip['TAG'] in ('PBG_C','PBG_E'):
                            if fslip[u'第一个策略产品A/T'] < 0.9:
                                    this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.9)'
                                    this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        if fslip['TAG'] in ('RE2_MIX',):
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                            elif fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                            elif fslip[u'第一个策略产品A/T'] > 1.1:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.1)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                        if fslip['TAG'] in ('GIALL_C', 'GIALL_E'):
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                            elif fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        #OCMIX
                        if fslip['TAG'] in ('OCMIX',):
                            if fslip[u'第一个策略产品A/T'] < 0.9 and fslip[u'第二个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.85||'
                            if fslip[u'第一个策略产品A/T'] < 0.9 or fslip[u'第二个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(一个策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                    else:
                        if fslip['TAG'] in ('OCMIX_E','PBG_C','PBG_E'):
                            if fslip[u'第一个策略产品A/T'] < 0.9:
                                    this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.9)'
                                    this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        if fslip['TAG'] in ('RE2',) and fslip[u'月均Symbicort指标大于等于2500']:
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                            elif fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                            elif fslip[u'第一个策略产品A/T'] > 1.1:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.1)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                        if fslip['TAG'] in ('GIALL_C', 'GIALL_E'):
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                            elif fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        if fslip['TAG'] in ('BCAF',):
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        #OCMIX
                        if fslip['TAG'] in ('OCMIX_C',):
                            if fslip[u'第一个策略产品A/T'] < 0.9 and fslip[u'第二个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.85||'
                            if fslip[u'第一个策略产品A/T'] < 0.9 or fslip[u'第二个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(一个策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                    # 检查起奖线
                    if fslip['TAG'] in ('CVB', 'DMO', 'RE3', 'BCA', 'BCAF', 'BCF', 'BCZ', 'BCAZ', 'OCMIX_C', 'OCMIX',
                                     'OCMIX_E', 'PBG_C', 'PBG_E', 'LCI', 'LCI_1', 'LCI_2'):
                        if fslip[u'结构内产品A/T'] < 0.6:
                            this_slip['formulas'] += [{'title': '因为结构内产品A/T < 60%',
                                                       'formula': 'YTD达成贡献奖 = 0',
                                                       'raw': True}]
                    else:
                        if fslip[u'结构内产品A/T'] < 0.8:
                            this_slip['formulas'] += [{'title': '因为结构内产品A/T < 80%',
                                                       'formula': 'YTD达成贡献奖 = 0',
                                                       'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2016年BCBH代表达成贡献奖') or slip_title.startswith('2016年H2BCBH代表达成贡献奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': display_order,
                                 'formulas': [{'title': 'YTD达成贡献奖',
                                               'formula': '||达成贡献奖|| = ||奖金基数|| * ||在岗月份数|| * ||贡献率系数|| * '}]}
                    if this_slip['slip'][u'TAG标准人均生产力'] == -1:
                        this_slip['slip'][u'TAG标准人均生产力'] = '-'
                    if (fslip['TAG'] in ('CVB', 'DMO', 'DMB', 'DMX', 'BCF') and fslip[u'产品1达成率'] >= 0.6) or fslip[u'产品1达成率'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||产品1A/T系数|| * ||产品1奖金权重||'
                    else:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||0||'
                    if fslip['TAG'] in ('DMX', 'BCAF') and fslip[u'产品2达成率'] >= 0.6 or fslip[u'产品2达成率'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += ' + ||产品2A/T系数|| * ||产品2奖金权重||'
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0||'
                    if fslip[u'产品3达成率'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += ' + ||产品3A/T系数|| * ||产品3奖金权重|| ||)||'
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0|| ||)||'
                    # 检查策略产品A/T
                    if '2016年7月' in slip_title or '2016年6~7月' in slip_title or '2016年8月' in slip_title or '2016年6~8月' in slip_title or '2016年9月' in slip_title or '2016年6~9月' in slip_title or '2016年10月' in slip_title or '2016年6~10月' in slip_title or '2016年11月' in slip_title or '2016年6~11月' or '2016年12月' in slip_title or '2016年6~12月' in slip_title:
                        if fslip['TAG'] in ('GIALL', 'ANA', 'RE2'):
                            if fslip[u'策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.8||'
                            if fslip[u'策略产品A/T'] >= 1.2:
                                # this_slip['slip'][u'最终增长奖金'] /= 1.2
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T >= 1.2)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.2||'
                        # 下半年开始OCMIX和PBG的策略产品A/T影响系数变化
                        if fslip['TAG'] in ('OCMIX', 'PBG'):
                            if fslip[u'策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.8||'
                    else:
                        if fslip['TAG'] in ('CVPB', 'GIALL', 'ANA', 'RE2', 'OCMIX'):
                            if fslip[u'策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.8||'
                            if fslip[u'策略产品A/T'] >= 1.2:
                                # this_slip['slip'][u'最终增长奖金'] /= 1.2
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T >= 1.2)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.2||'
                    # 检查起奖线
                    if fslip['TAG'] in ('CVB', 'DMO', 'DMB', 'DMX', 'BCF'):
                        if fslip[u'结构内产品A/T'] < 0.6:
                            this_slip['formulas'] += [{'title': '因为结构内产品A/T < 60%',
                                                       'formula': 'YTD达成贡献奖 = 0',
                                                       'raw': True}]
                    else:
                        if fslip[u'结构内产品A/T'] < 0.8:
                            this_slip['formulas'] += [{'title': '因为结构内产品A/T < 80%',
                                                       'formula': 'YTD达成贡献奖 = 0',
                                                       'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2016年Q2CV代表达成贡献奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': display_order,
                                 'formulas': [{'title': 'YTD达成贡献奖',
                                               'formula': '||达成贡献奖|| = ||奖金基数|| * ||在岗月份数|| * ||贡献率系数|| * '}]}
                    if this_slip['slip'][u'TAG标准人均生产力'] == -1:
                        this_slip['slip'][u'TAG标准人均生产力'] = '-'
                    if fslip[u'产品1达成率'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||产品1A/T系数|| * ||产品1奖金权重||'
                    else:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||0||'
                    if fslip[u'产品2达成率'] >= 0.8:
                        this_slip['formulas'][-1]['formula'] += ' + ||产品2A/T系数|| * ||产品2奖金权重|| ||)||'
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0|| ||)||'
                    # 检查起奖线
                    if fslip[u'结构内产品A/T'] < 0.8:
                        this_slip['formulas'] += [{'title': '因为结构内产品A/T < 80%',
                                                   'formula': 'YTD达成贡献奖 = 0',
                                                   'raw': True}]
                    all_slips.append(this_slip)
            if slip_title.startswith('2016年BCBH代表增长奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': ['员工号', 'TAG', '员工姓名', '在岗月份数', '策略产品A/T',
                                                   '标准增长奖金', '额外增长奖金', '最终增长奖金', '结构内产品A/T'],
                                 'formulas': [{'title': 'YTD最终增长奖金',
                                               'formula': '||最终增长奖金|| = ||标准增长奖金|| + ||额外增长奖金||'}]}
                    if fslip['TAG'] == 'CVB':
                        this_slip['display_order'] += ['Brilinta标准增长金额', 'Brilinta额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Brilinta标准增长金额|| * ||0.133||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Brilinta额外增长金额|| * ||0.132||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'CVC':
                        this_slip['display_order'] += ['Crestor标准增长金额', 'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.166|| + ||Brilinta标准增长金额|| * ||0.133||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'CVK':
                        this_slip['display_order'] += ['Betaloc ZOK标准增长金额', 'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Betaloc ZOK标准增长金额|| * ||0.195|| + ||Brilinta标准增长金额|| * ||0.133||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'CVPB':
                        this_slip['display_order'] += ['Betaloc ZOK标准增长金额', 'Plendil标准增长金额', 'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Betaloc ZOK标准增长金额|| * ||0.225|| + ||Plendil标准增长金额|| * ||0.2|| + ||Brilinta标准增长金额|| * ||0.133||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'CVX':
                        this_slip['display_order'] += ['Crestor标准增长金额', 'Betaloc ZOK标准增长金额', 'Plendil标准增长金额',
                                                       'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.13|| + ||Betaloc ZOK标准增长金额|| * ||0.13|| + ||Plendil标准增长金额|| * ||0.09|| + ||Brilinta标准增长金额|| * ||0.133||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'DMO':
                        if '2016年4月' in slip_title or '2016年5月' in slip_title or '2016年6月' in slip_title:
                            this_slip['display_order'] += ['Onglyza标准增长金额', 'Byetta标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Onglyza标准增长金额|| * ||0.245|| + ||Byetta标准增长金额|| * ||0.2||'}] + \
                                                    this_slip['formulas']
                        else:
                            this_slip['display_order'] += ['Onglyza标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Onglyza标准增长金额|| * ||0.245||'}] + \
                                                    this_slip['formulas']
                    elif fslip['TAG'] == 'DMB':
                        this_slip['display_order'] += ['Byetta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Byetta标准增长金额|| * ||0.22||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'DMX':
                        this_slip['display_order'] += ['Onglyza标准增长金额', 'Byetta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Onglyza标准增长金额|| * ||0.22|| + ||Byetta标准增长金额|| * ||0.2||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'ANA':
                        this_slip['display_order'] += ['Diprivan 20ml标准增长金额', 'Diprivan PFS标准增长金额', 'Naropin标准增长金额',
                                                       'Naropin额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Diprivan 20ml标准增长金额|| * ||0.08|| + ||Diprivan PFS标准增长金额|| * ||0.08|| + ||Naropin标准增长金额|| * ||0.1||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Naropin额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'GIOral':
                        this_slip['display_order'] += ['Nexium Oral标准增长金额', 'Nexium Oral额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Nexium Oral标准增长金额|| * ||0.165||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Nexium Oral额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'GIIV':
                        this_slip['display_order'] += ['Nexium IV标准增长金额', 'Nexium IV额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Nexium IV标准增长金额|| * ||0.115||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Nexium IV额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'GIALL':
                        this_slip['display_order'] += ['Nexium Oral标准增长金额', 'Nexium Oral额外增长金额', 'Nexium IV标准增长金额',
                                                       'Nexium IV额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Nexium Oral标准增长金额|| * ||0.12|| + ||Nexium IV标准增长金额|| * ||0.09||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Nexium Oral额外增长金额|| * ||0.05|| + ||Nexium IV额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'GA':
                        this_slip['display_order'] += ['Diprivan 20ml标准增长金额', 'Diprivan PFS标准增长金额',
                                                       'Naropin标准增长金额', 'Nexium Oral标准增长金额', 'Nexium IV标准增长金额',
                                                       'Naropin额外增长金额', 'Nexium Oral额外增长金额', 'Nexium IV额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Diprivan 20ml标准增长金额|| * ||0.07|| + ||Diprivan PFS标准增长金额|| * ||0.07|| + ||Naropin标准增长金额|| * ||0.08|| + ||Nexium Oral标准增长金额|| * ||0.12|| + ||Nexium IV标准增长金额|| * ||0.07||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Nexium IV额外增长金额|| * ||0.05|| + ||Nexium Oral额外增长金额|| * ||0.05|| + ||Naropin额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'RE1':
                        this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Bricanyl N.S.标准增长金额',
                                                       'Pul.Respules0.5mg标准增长金额', 'Symbicort 80/160d标准增长金额',
                                                       'Pul.Respules0.5mg额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.059|| + ||Bricanyl N.S.标准增长金额|| * ||0.058|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.114|| + ||Symbicort 80/160d标准增长金额|| * ||0.075||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.028||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'RE3':
                        this_slip['display_order'] += ['Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额',
                                                       'Rhinocort标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Symbicort 80/160d标准增长金额|| * ||0.098|| + ||Symbicort 320d标准增长金额|| * ||0.15|| + ||Rhinocort标准增长金额|| * ||0.07||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'RE2':
                        this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Pul.Respules0.5mg标准增长金额',
                                                       'Rhinocort标准增长金额', 'Symbicort 80/160d标准增长金额',
                                                       'Symbicort 320d标准增长金额', 'Bricanyl N.S.标准增长金额',
                                                       'Pul.Respules0.5mg额外增长金额']
                        if '2016年4月' in slip_title or '2016年5月' in slip_title or '2016年6月' in slip_title:
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.05|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.114|| + ||Rhinocort标准增长金额|| * ||0.07|| + ||Symbicort 80/160d标准增长金额|| * ||0.11|| + ||Symbicort 320d标准增长金额|| * ||0.11|| + ||Bricanyl N.S.标准增长金额|| * ||0.05||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.028||'}] + \
                                                    this_slip['formulas']
                        else:
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.05|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.114|| + ||Rhinocort标准增长金额|| * ||0.07|| + ||Symbicort 80/160d标准增长金额|| * ||0.075|| + ||Symbicort 320d标准增长金额|| * ||0.1|| + ||Bricanyl N.S.标准增长金额|| * ||0.05||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.028||'}] + \
                                                    this_slip['formulas']
                    elif fslip['TAG'] == 'RE-R':
                        this_slip['display_order'] += ['Rhinocort标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Rhinocort标准增长金额|| * ||0.07||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'BCA':
                        this_slip['display_order'] += ['Arimidex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Arimidex标准增长金额|| * ||0.09||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'BCF':
                        this_slip['display_order'] += ['Faslodex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Faslodex标准增长金额|| * ||0.058||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'BCAF':
                        this_slip['display_order'] += ['Arimidex标准增长金额', 'Faslodex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Arimidex标准增长金额|| * ||0.11|| + ||Faslodex标准增长金额|| * ||0.06||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'BCZ':
                        this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.114|| + ||Zoladex10.8mg标准增长金额|| * ||0.114||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'PBG':
                        this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Casodex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.06|| + ||Zoladex10.8mg标准增长金额|| * ||0.065|| + ||Casodex标准增长金额|| * ||0.06||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'OCMIX':
                        this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Arimidex标准增长金额',
                                                       'Casodex标准增长金额', 'Faslodex标准增长金额', 'Iressa标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.06|| + ||Zoladex10.8mg标准增长金额|| * ||0.085|| + ||Arimidex标准增长金额|| * ||0.09|| + ||Casodex标准增长金额|| * ||0.04|| + ||Faslodex标准增长金额|| * ||0.06|| + ||Iressa标准增长金额|| * ||0.08||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'LC':
                        this_slip['display_order'] += ['Iressa标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Iressa标准增长金额|| * ||0.116||'}] + \
                                                this_slip['formulas']
                    else:
                        pass
                    # 检查策略产品A/T
                    if fslip['TAG'] in ('CVPB', 'GIALL', 'ANA', 'RE2', 'OCMIX'):
                        if fslip[u'策略产品A/T'] < 0.8:
                            # this_slip['slip'][u'最终增长奖金'] /= 0.8
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                            this_slip['formulas'][-1][
                                'formula'] = '||最终增长奖金|| = ||(|| ||标准增长奖金|| + ||额外增长奖金|| ||)|| * ||0.8||'
                        if fslip[u'策略产品A/T'] >= 1.2:
                            # this_slip['slip'][u'最终增长奖金'] /= 1.2
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T >= 1.2)'
                            this_slip['formulas'][-1][
                                'formula'] = '||最终增长奖金|| = ||(|| ||标准增长奖金|| + ||额外增长奖金|| ||)|| * ||1.2||'
                    # 检查起奖线
                    if fslip['TAG'] in ('CVB', 'DMO', 'DMB', 'DMX', 'BCF'):
                        if fslip[u'结构内产品A/T'] < 0.6:
                            this_slip['formulas'] += [{'title': '因为结构内产品A/T < 60%',
                                                       'formula': 'YTD最终增长奖金 = 0',
                                                       'raw': True}]
                    else:
                        if fslip[u'结构内产品A/T'] < 0.8:
                            this_slip['formulas'] += [{'title': '因为结构内产品A/T < 80%',
                                                       'formula': 'YTD最终增长奖金 = 0',
                                                       'raw': True}]
                    all_slips.append(this_slip)
            # 下半年增长奖变化较大，单独处理
            if slip_title.startswith('2017年BCBH代表增长奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': ['员工号', 'TAG', '员工姓名', '在岗月份数', '策略产品A/T',
                                                   '标准增长奖金', '额外增长奖金', '最终增长奖金'],
                                 'formulas': [{'title': 'YTD最终增长奖金',
                                                   'formula': '||最终增长奖金|| = ||标准增长奖金|| + ||额外增长奖金||'}]}
                    if 'H2' in slip_title:
                        if fslip['TAG'] == 'CVB':
                            this_slip['display_order'] += ['Brilinta标准增长金额', 'Brilinta额外增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Brilinta标准增长金额|| * ||0.105||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Brilinta额外增长金额|| * ||0.052||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CVC':
                            this_slip['display_order'] += ['Crestor标准增长金额', 'Brilinta标准增长金额', 'Onglyza标准增长金额',
                                                           'Kombiglyze标准增长金额', 'Forxiga标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.08|| + ||Onglyza标准增长金额|| * ||0.21|| + ||Kombiglyze标准增长金额|| * ||0.07|| + ||Forxiga标准增长金额|| * ||0.15|| + ||Brilinta标准增长金额|| * ||0.105||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CVK':
                            this_slip['display_order'] += ['Betaloc ZOK标准增长金额', 'Brilinta标准增长金额', 'Onglyza标准增长金额',
                                                           'Kombiglyze标准增长金额', 'Forxiga标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Betaloc ZOK标准增长金额|| * ||0.1|| + ||Onglyza标准增长金额|| * ||0.21|| + ||Kombiglyze标准增长金额|| * ||0.07|| + ||Forxiga标准增长金额|| * ||0.15|| + ||Brilinta标准增长金额|| * ||0.105||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CVX_C':
                            this_slip['display_order'] += ['Crestor标准增长金额', 'Betaloc ZOK标准增长金额', 'Brilinta标准增长金额',
                                                           'Onglyza标准增长金额', 'Kombiglyze标准增长金额', 'Forxiga标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.06|| + ||Betaloc ZOK标准增长金额|| * ||0.06|| + ||Onglyza标准增长金额|| * ||0.21|| + ||Kombiglyze标准增长金额|| * ||0.07|| + ||Forxiga标准增长金额|| * ||0.15|| + ||Brilinta标准增长金额|| * ||0.105||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CVX_E':
                            this_slip['display_order'] += ['Crestor标准增长金额', 'Betaloc ZOK标准增长金额', 'Brilinta标准增长金额',
                                                           'Onglyza标准增长金额', 'Kombiglyze标准增长金额', 'Forxiga标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.105|| + ||Betaloc ZOK标准增长金额|| * ||0.105|| + ||Onglyza标准增长金额|| * ||0.21|| + ||Kombiglyze标准增长金额|| * ||0.07|| + ||Forxiga标准增长金额|| * ||0.15|| + ||Brilinta标准增长金额|| * ||0.105||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'DMO':
                            this_slip['display_order'] += ['Onglyza标准增长金额', 'Kombiglyze标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Onglyza标准增长金额|| * ||0.33|| + + ||Kombiglyze标准增长金额|| * ||0.10||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'GIOral':
                            this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.095||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'GIIV':
                            this_slip['display_order'] += ['NexiumIV+LosecIV标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||NexiumIV+LosecIV标准增长金额|| * ||0.065||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'GIALL_C':
                            this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额', 'NexiumIV+LosecIV标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.09|| + ||NexiumIV+LosecIV标准增长金额|| * ||0.04||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'GIALL_E':
                            this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额', 'NexiumIV+LosecIV标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.16|| + ||NexiumIV+LosecIV标准增长金额|| * ||0.1||'}] + \
                                                    this_slip['formulas']
                        # elif fslip['TAG'] == 'ANA':
                        #     this_slip['display_order'] += ['Diprivan 20ml标准增长金额', 'Diprivan PFS标准增长金额', 'Naropin标准增长金额']
                        #     this_slip['formulas'] += [{'title': 'YTD标准增长奖金',
                        #                                'formula': '||标准增长奖金|| = ||Diprivan 20ml标准增长金额|| * ||0.05|| + ||Diprivan PFS标准增长金额|| * ||0.06|| + ||Naropin标准增长金额|| * ||0.07||'}] + \
                        #                              this_slip['formulas']
                        elif fslip['TAG'] == 'RE1':
                            this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Bricanyl N.S.标准增长金额',
                                                           'Pul.Respules0.5mg标准增长金额', 'Pul.Respules0.5mg额外增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.06|| + ||Bricanyl N.S.标准增长金额|| * ||0.045|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.11||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.03||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'].upper() == 'RE2_PB':
                            this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Pul.Respules0.5mg标准增长金额',
                                                           'Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额',
                                                           'Bricanyl N.S.标准增长金额', 'Pul.Respules0.5mg额外增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.098|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.13|| + ||Symbicort 80/160d标准增长金额|| * ||0.18|| + ||Symbicort 320d标准增长金额|| * ||0.20|| + ||Bricanyl N.S.标准增长金额|| * ||0.1||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.03||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'].upper() == 'RE2_MIX':
                            this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Pul.Respules0.5mg标准增长金额',
                                                           'Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额',
                                                           'Bricanyl N.S.标准增长金额', 'Pul.Respules0.5mg额外增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.075|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.11|| + ||Symbicort 80/160d标准增长金额|| * ||0.22|| + ||Symbicort 320d标准增长金额|| * ||0.24|| + ||Bricanyl N.S.标准增长金额|| * ||0.05||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.03||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'RE3':
                            this_slip['display_order'] += ['Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Symbicort 80/160d标准增长金额|| * ||0.185|| + ||Symbicort 320d标准增长金额|| * ||0.205||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CHC':
                            this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Pul.Respules0.5mg标准增长金额',
                                                           'Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额',
                                                           'Bricanyl N.S.标准增长金额', 'Pul.Respules0.5mg额外增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.05|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.11|| + ||Symbicort 80/160d标准增长金额|| * ||0.22|| + ||Symbicort 320d标准增长金额|| * ||0.24|| + ||Bricanyl N.S.标准增长金额|| * ||0.05||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.03||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'BCA' or fslip['TAG'] == 'BCAF':
                            this_slip['display_order'] += ['Arimidex标准增长金额', 'Faslodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Arimidex标准增长金额|| * ||0.08|| + ||Faslodex标准增长金额|| * ||0.077||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'BCF':
                            this_slip['display_order'] += ['Faslodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Faslodex标准增长金额|| * ||0.077||'}] + \
                                                    this_slip['formulas']
                        # elif fslip['TAG'] == 'BCAF':
                        #     this_slip['display_order'] += ['Arimidex标准增长金额', 'Faslodex标准增长金额']
                        #     this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                        #                               'formula': '||标准增长奖金|| = ||Arimidex标准增长金额|| * ||0.095|| + ||Faslodex标准增长金额|| * ||0.09||'}] + \
                        #                             this_slip['formulas']
                        elif fslip['TAG'] == 'BCAZ':
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Arimidex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.05|| + ||Arimidex标准增长金额|| * ||0.05||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'OCMIX':
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Arimidex标准增长金额',
                                                           'Casodex标准增长金额', 'Faslodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.075|| + ||Zoladex10.8mg标准增长金额|| * ||0.105|| + ||Arimidex标准增长金额|| * ||0.075|| + ||Casodex标准增长金额|| * ||0.075|| + ||Faslodex标准增长金额|| * ||0.075||'}] + \
                                                    this_slip['formulas']
                        # elif fslip['TAG'] == 'OCMIX_E':
                        #     this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Arimidex标准增长金额',
                        #                                    'Casodex标准增长金额', 'Faslodex标准增长金额']
                        #     this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                        #                               'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.065|| + ||Zoladex10.8mg标准增长金额|| * ||0.095|| + ||Arimidex标准增长金额|| * ||0.065|| + ||Casodex标准增长金额|| * ||0.065|| + ||Faslodex标准增长金额|| * ||0.065||'}] + \
                        #                             this_slip['formulas']
                        elif fslip['TAG'] == 'PBG_C':
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Casodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.035|| + ||Zoladex10.8mg标准增长金额|| * ||0.05|| + ||Casodex标准增长金额|| * ||0.035||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'PBG_E':
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Casodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.085|| + ||Zoladex10.8mg标准增长金额|| * ||0.1|| + ||Casodex标准增长金额|| * ||0.085||'}] + \
                                                    this_slip['formulas']
                    else:
                        if fslip['TAG'] == 'CVB':
                            this_slip['display_order'] += ['Brilinta标准增长金额', 'Brilinta额外增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Brilinta标准增长金额|| * ||0.105||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Brilinta额外增长金额|| * ||0.052||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CVC':
                            this_slip['display_order'] += ['Crestor标准增长金额', 'Brilinta标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.08|| + ||Brilinta标准增长金额|| * ||0.105||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CVK':
                            this_slip['display_order'] += ['Betaloc ZOK标准增长金额', 'Brilinta标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Betaloc ZOK标准增长金额|| * ||0.1|| + ||Brilinta标准增长金额|| * ||0.105||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CVX_C':
                            this_slip['display_order'] += ['Crestor标准增长金额', 'Betaloc ZOK标准增长金额', 'Brilinta标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.06|| + ||Betaloc ZOK标准增长金额|| * ||0.06|| + ||Brilinta标准增长金额|| * ||0.105||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CVX_E':
                            this_slip['display_order'] += ['Crestor标准增长金额', 'Betaloc ZOK标准增长金额', 'Brilinta标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.105|| + ||Betaloc ZOK标准增长金额|| * ||0.105|| + ||Brilinta标准增长金额|| * ||0.105||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'DMO':
                            this_slip['display_order'] += ['Onglyza标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                        'formula': '||标准增长奖金|| = ||Onglyza标准增长金额|| * ||0.33||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'GIOral':
                            this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.09||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'GIIV':
                            this_slip['display_order'] += ['NexiumIV+LosecIV标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||NexiumIV+LosecIV标准增长金额|| * ||0.115||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'GIALL_C':
                            this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额', 'NexiumIV+LosecIV标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.065|| + ||NexiumIV+LosecIV标准增长金额|| * ||0.04||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'GIALL_E':
                            this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额', 'NexiumIV+LosecIV标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.15|| + ||NexiumIV+LosecIV标准增长金额|| * ||0.1||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'ANA':
                            this_slip['display_order'] += ['Diprivan 20ml标准增长金额', 'Diprivan PFS标准增长金额', 'Naropin标准增长金额']
                            this_slip['formulas'] += [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Diprivan 20ml标准增长金额|| * ||0.05|| + ||Diprivan PFS标准增长金额|| * ||0.06|| + ||Naropin标准增长金额|| * ||0.07||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'RE1':
                            this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Bricanyl N.S.标准增长金额',
                                                           'Pul.Respules0.5mg标准增长金额', 'Pul.Respules0.5mg额外增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.045|| + ||Bricanyl N.S.标准增长金额|| * ||0.04|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.11||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.03||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'RE2':
                            this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Pul.Respules0.5mg标准增长金额',
                                                           'Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额',
                                                           'Bricanyl N.S.标准增长金额', 'Pul.Respules0.5mg额外增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.05|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.11|| + ||Symbicort 80/160d标准增长金额|| * ||0.22|| + ||Symbicort 320d标准增长金额|| * ||0.24|| + ||Bricanyl N.S.标准增长金额|| * ||0.05||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.03||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'RE3':
                            this_slip['display_order'] += ['Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Symbicort 80/160d标准增长金额|| * ||0.24|| + ||Symbicort 320d标准增长金额|| * ||0.27||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'CHC':
                            this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Pul.Respules0.5mg标准增长金额',
                                                           'Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额',
                                                           'Bricanyl N.S.标准增长金额', 'Pul.Respules0.5mg额外增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.05|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.11|| + ||Symbicort 80/160d标准增长金额|| * ||0.22|| + ||Symbicort 320d标准增长金额|| * ||0.24|| + ||Bricanyl N.S.标准增长金额|| * ||0.05||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.03||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'BCA':
                            this_slip['display_order'] += ['Arimidex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Arimidex标准增长金额|| * ||0.085||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'BCF':
                            this_slip['display_order'] += ['Faslodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Faslodex标准增长金额|| * ||0.077||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'BCAF':
                            this_slip['display_order'] += ['Arimidex标准增长金额', 'Faslodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Arimidex标准增长金额|| * ||0.095|| + ||Faslodex标准增长金额|| * ||0.09||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'BCZ':
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.07||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'OCMIX_C':
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Arimidex标准增长金额',
                                                           'Casodex标准增长金额', 'Faslodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.05|| + ||Zoladex10.8mg标准增长金额|| * ||0.08|| + ||Arimidex标准增长金额|| * ||0.05|| + ||Casodex标准增长金额|| * ||0.05|| + ||Faslodex标准增长金额|| * ||0.05||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'OCMIX_E':
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Arimidex标准增长金额',
                                                           'Casodex标准增长金额', 'Faslodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.065|| + ||Zoladex10.8mg标准增长金额|| * ||0.095|| + ||Arimidex标准增长金额|| * ||0.065|| + ||Casodex标准增长金额|| * ||0.065|| + ||Faslodex标准增长金额|| * ||0.065||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'PBG_C':
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Casodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.04|| + ||Zoladex10.8mg标准增长金额|| * ||0.06|| + ||Casodex标准增长金额|| * ||0.04||'}] + \
                                                    this_slip['formulas']
                        elif fslip['TAG'] == 'PBG_E':
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Casodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.075|| + ||Zoladex10.8mg标准增长金额|| * ||0.1|| + ||Casodex标准增长金额|| * ||0.075||'}] + \
                                                    this_slip['formulas']
                        # 策略产品
                        if fslip['TAG'] in ('OCMIX_E', 'PBG_C', 'PBG_E'):
                            if fslip[u'第一个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        if fslip['TAG'] in ('RE2',) and fslip[u'月均Symbicort指标大于2500']:
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                            elif fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                            elif fslip[u'第一个策略产品A/T'] > 1.1:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.1)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                        if fslip['TAG'] in ('GIALL_C', 'GIALL_E'):
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                            elif fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        if fslip['TAG'] in ('BCAF',):
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        # OCMIX
                        if fslip['TAG'] in ('OCMIX_C',):
                            if fslip[u'第一个策略产品A/T'] < 0.9 and fslip[u'第二个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.85||'
                            if fslip[u'第一个策略产品A/T'] < 0.9 or fslip[u'第二个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(一个策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                    # 检查起奖线
                all_slips.append(this_slip)
            if slip_title.startswith('2018年BCBH&County代表达成贡献奖'):
                idx = 0
                # 补入产品与策略产品
                prod_info = {}
                with open('incentivepower/conf/az_prod_weight.json', 'rb') as prod_weight_json:
                    prod_info = json.load(prod_weight_json)
                prod_weight = prod_info['2018H1']['achi_weight'] # 权重
                prod_strategic = prod_info['2018H1']['achi_strategic'] # 捆绑
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 # 重构每个排序
                                 'display_order': ['员工号', '员工姓名', 'TAG', '在岗月份', '在岗月份数', '月均实际销售额',
                                                   'TAG标准人均生产力', '封顶前贡献率系数', '贡献率系数', '奖金基数'],
                                 'formulas': [{'title': 'YTD达成贡献奖',
                                               'formula': '||达成贡献奖|| = ||奖金基数|| * ||在岗月份数|| * ||贡献率系数|| * '}]}
                    # CVB不考核人均生产力
                    if this_slip['slip'][u'TAG标准人均生产力'] == -1:
                        this_slip['slip'][u'TAG标准人均生产力'] = '-'
                    # 起奖线 OCMIX与BCAZ为H2 TAGS
                    if (fslip['TAG'] in ('DMF', 'DMX', 'GMX_ALL', 'GMX_EAGLE', 'CVB', 'DMO', 'BCA', 'BCAF',
                                         'BCF', 'BCAZ', 'OCMIX', 'PBG_C', 'PBG_E', 'LCI_1', 'LCI_2', 'LCIT_1', 'LCIT_2',
                                         'BCZ', 'LCI', 'LCIT_C', 'LCIT_E', 'LCT', 'CU_CHC', 'CT', 'CT_P2'
                                         )) and fslip[u'产品1达成率'] >= 0.6 or fslip[u'产品1达成率'] >= 0.8:
                        this_slip['display_order'] += [u'产品1', u'产品1销量', u'产品1指标', u'产品1达成率',
                                                       u'产品1A/T系数', u'产品1奖金权重']
                        this_slip['formulas'][-1]['formula'] += '||(|| ||产品1A/T系数|| * ||产品1奖金权重||'
                        this_slip['slip'][u'产品1'] = prod_weight.get(fslip['TAG'], [''])[0]
                    else:
                        this_slip['formulas'][-1]['formula'] += '||(|| ||0||'
                    if (fslip['TAG'] in ('DMF', 'DMX', 'GMX_ALL', 'GMX_EAGLE', 'CVB', 'DMO', 'BCA', 'BCAF',
                                         'BCF', 'BCAZ', 'OCMIX', 'PBG_C', 'PBG_E', 'LCI_1', 'LCI_2', 'LCIT_1', 'LCIT_2',
                                         'BCZ', 'LCI', 'LCIT_C', 'LCIT_E', 'LCT', 'CU_CHC', 'CT', 'CT_P2'
                                         )) and fslip[u'产品2达成率'] >= 0.6 or fslip[u'产品2达成率'] >= 0.8:
                        this_slip['display_order'] += [u'产品2', u'产品2销量', u'产品2指标', u'产品2达成率',
                                                       u'产品2A/T系数', u'产品2奖金权重']
                        this_slip['formulas'][-1]['formula'] += ' + ||产品2A/T系数|| * ||产品2奖金权重||'
                        this_slip['slip'][u'产品2'] = prod_weight.get(fslip['TAG'], ['', ''])[1]
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0||'
                    if (fslip['TAG'] in ('DMF', 'DMX', 'GMX_ALL', 'GMX_EAGLE', 'CVB', 'DMO', 'BCA', 'BCAF',
                                         'BCF', 'BCAZ', 'OCMIX', 'PBG_C', 'PBG_E', 'LCI_1', 'LCI_2', 'LCIT_1', 'LCIT_2',
                                         'BCZ', 'LCI', 'LCIT_C', 'LCIT_E', 'LCT', 'CU_CHC', 'CT', 'CT_P2'
                                         )) and fslip[u'产品3达成率'] >= 0.6 or fslip[u'产品3达成率'] >= 0.8:
                        this_slip['display_order'] += [u'产品3', u'产品3销量', u'产品3指标', u'产品3达成率',
                                                       u'产品3A/T系数', u'产品3奖金权重']
                        this_slip['formulas'][-1]['formula'] += ' + ||产品3A/T系数|| * ||产品3奖金权重|| ||)||'
                        this_slip['slip'][u'产品3'] = prod_weight.get(fslip['TAG'], ['', '', ''])[2]
                    else:
                        this_slip['formulas'][-1]['formula'] += ' + ||0|| ||)||'
                    if fslip['TAG'] in ('RE2_Mix',):
                        this_slip['display_order'] += [u'第一个策略产品', u'第一个策略产品A/T', u'策略产品系数']
                        this_slip['slip'][u'第一个策略产品'] = prod_strategic.get(fslip['TAG'], [''])[0]
                        if fslip[u'第一个策略产品A/T'] < 0.8:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                            this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        elif 1.1 > fslip[u'第一个策略产品A/T'] > 1.0:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        elif fslip[u'第一个策略产品A/T'] > 1.1:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.1)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                    #OCMIX
                    if fslip['TAG'] in ('OCMIX',):
                        this_slip['display_order'] += [u'第一个策略产品', u'第一个策略产品A/T',
                                                       u'第二个策略产品', u'第二个策略产品A/T', u'策略产品系数']
                        this_slip['slip'][u'第一个策略产品'] = prod_strategic.get(fslip['TAG'], [''])[0]
                        this_slip['slip'][u'第二个策略产品'] = prod_strategic.get(fslip['TAG'], ['', ''])[1]
                        if fslip[u'第一个策略产品A/T'] < 0.9 and fslip[u'第二个策略产品A/T'] < 0.9:
                            this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9)'
                            this_slip['formulas'][-1]['formula'] += ' * ||0.85||'
                        elif fslip[u'第一个策略产品A/T'] < 0.9 or fslip[u'第二个策略产品A/T'] < 0.9:
                            this_slip['formulas'][-1]['title'] += '(一个策略产品A/T < 0.9)'
                            this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        elif (1.0 > fslip[u'第一个策略产品A/T'] > 0.9) and (fslip[u'第二个策略产品A/T'] > 1.0):
                            this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9且一个策略产品A/T > 1.0)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        elif (1.0 > fslip[u'第二个策略产品A/T'] > 0.9) and (fslip[u'第一个策略产品A/T'] > 1.0):
                            this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9且一个策略产品A/T > 1.0)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        elif fslip[u'第一个策略产品A/T'] > 1.0 and fslip[u'第二个策略产品A/T'] > 1.0:
                            this_slip['formulas'][-1]['title'] += '(两个策略产品A/T > 1.0)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                    if fslip['TAG'] in ('PBG_C','PBG_E'):
                        this_slip['display_order'] += [u'第一个策略产品', u'第一个策略产品A/T', u'策略产品系数']
                        this_slip['slip'][u'第一个策略产品'] = prod_strategic.get(fslip['TAG'], [''])[0]
                        if fslip[u'第一个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        if fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                    if fslip['TAG'] in ('GIALL_C', 'GIALL_E', 'GMX_CVM'):
                        this_slip['display_order'] += [u'第一个策略产品', u'第一个策略产品A/T', u'策略产品系数']
                        this_slip['slip'][u'第一个策略产品'] = prod_strategic.get(fslip['TAG'], [''])[0]
                        if fslip[u'第一个策略产品A/T'] < 0.8:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                            this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        elif 1.1 > fslip[u'第一个策略产品A/T'] > 1.0:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        elif fslip[u'第一个策略产品A/T'] > 1.1:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.1)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                    # 策略产品
                    # if 'H2' in slip_title:
                    #     if fslip['TAG'] in ('PBG_C','PBG_E'):
                    #         if fslip[u'第一个策略产品A/T'] < 0.9:
                    #                 this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.9)'
                    #                 this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                    #     if fslip['TAG'] in ('RE2_MIX',):
                    #         if fslip[u'第一个策略产品A/T'] < 0.8:
                    #             this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                    #             this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                    #         elif fslip[u'第一个策略产品A/T'] > 1.0:
                    #             this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                    #             this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                    #         elif fslip[u'第一个策略产品A/T'] > 1.1:
                    #             this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.1)'
                    #             this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                    #     if fslip['TAG'] in ('GIALL_C', 'GIALL_E'):
                    #         if fslip[u'第一个策略产品A/T'] < 0.8:
                    #             this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                    #             this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                    #         elif fslip[u'第一个策略产品A/T'] > 1.0:
                    #             this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                    #             this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                    #     #OCMIX
                    #     if fslip['TAG'] in ('OCMIX',):
                    #         if fslip[u'第一个策略产品A/T'] < 0.9 and fslip[u'第二个策略产品A/T'] < 0.9:
                    #             this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9)'
                    #             this_slip['formulas'][-1]['formula'] += ' * ||0.85||'
                    #         if fslip[u'第一个策略产品A/T'] < 0.9 or fslip[u'第二个策略产品A/T'] < 0.9:
                    #             this_slip['formulas'][-1]['title'] += '(一个策略产品A/T < 0.9)'
                    #             this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                    # else:
                    # 检查起奖线
                    if fslip['TAG'] in ('CVB', 'DMF', 'DMO', 'DMX', 'GMX_ALL', 'CT', 'CT_P2', 'GMX_EAGLE', 'BCA',
                                        'BCAF', 'BCF', 'BCZ', 'BCAZ', 'LCI', 'LCIT_C', 'LCIT_E', 'LCT', 'OCMIX',
                                        'PBG_C', 'PBG_E', 'CU_CHC'):
                        this_slip['display_order'] += [u'结构内产品A/T']
                        if fslip[u'结构内产品A/T'] < 0.6:
                            this_slip['formulas'] += [{'title': '因为结构内产品A/T < 60%',
                                                       'formula': 'YTD达成贡献奖 = 0',
                                                       'raw': True}]
                    else:
                        this_slip['display_order'] += [u'结构内产品A/T']
                        if fslip[u'结构内产品A/T'] < 0.8:
                            this_slip['formulas'] += [{'title': '因为结构内产品A/T < 80%',
                                                       'formula': 'YTD达成贡献奖 = 0',
                                                       'raw': True}]
                    if fslip['TAG'] in ('LCIT_C', 'LCIT_E', 'LCT'):
                        this_slip['display_order'] += [u'Tagrisso季度月均指标盒数', u'Tagrisso销量', u'Tagrisso指标']
                    if fslip['TAG'] in ('LCIT_C', 'LCIT_E'):
                        this_slip['display_order'] += [u'Tagrisso特殊津贴', u'Tagrisso额外奖']
                    if fslip['TAG'] in ('LCT',):
                        this_slip['display_order'] += [u'Tagrisso金额贡献奖', u'Tagrisso特殊贡献奖']
                    if fslip['TAG'] in ('LCI', 'LCT'):
                        this_slip['display_order'] += [u'LC产品销量', u'LC产品指标', u'LC产品达成率',
                                                       u'LC产品系数', u'LC合作达成奖']
                    if fslip['TAG'] in ('LCIT_C', 'LCIT_E', 'LCI'):
                        this_slip['display_order'] += [u'达成贡献奖(Iressa)']
                    if fslip['TAG'] in ('LCT',):
                        this_slip['display_order'] += [u'达成贡献奖(Tagrisso)']
                    if fslip['TAG'] in ('RE1',):
                        this_slip['display_order'] += [u'SymbicortYTD是否负增长']
                    all_slips.append(this_slip)

            if slip_title.startswith('2018年BCBH&County代表增长奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': ['员工号', 'TAG', '员工姓名', '在岗月份数', '策略产品A/T',
                                                   '标准增长奖金', '额外增长奖金', '最终增长奖金'],
                                 'formulas': [{'title': 'YTD最终增长奖金',
                                                   'formula': '||最终增长奖金|| = ||标准增长奖金|| + ||额外增长奖金||'}]}
                    if fslip['TAG'].upper() == 'CVB':
                        b_target = fslip[u'Brilinta指标']
                        b_sales = fslip[u'Brilinta销量']
                        last_sales = fslip[u'2017H1月均销售金额'] * 0.78
                        this_slip['display_order'] += ['Brilinta标准增长金额', 'Brilinta额外增长金额', '2017H1月均销售金额']
                        if b_target <= last_sales and last_sales <= b_sales:
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||(|| ||Brilinta销量|| - ||2017H1月均销售金额|| * ||0.78|| ||)||* ||0.15||'}] + \
                                                    this_slip['formulas']
                        elif b_sales <= b_target and b_target > last_sales and b_sales >= last_sales:
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||(|| ||Brilinta销量|| - ||2017H1月均销售金额|| * ||0.78|| ||)||* ||0.1||'}] + \
                                                    this_slip['formulas']
                        elif b_sales >= b_target and b_target > last_sales and last_sales <= b_sales:
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||(|| ||Brilinta指标|| - ||2017H1月均销售金额|| * ||0.78|| ||)||* ||0.1||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||Brilinta额外增长金额|| * ||0.15||'}] + \
                                                    this_slip['formulas']
                        else:
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||0||'},
                                                     {'title': 'YTD额外增长奖金',
                                                      'formula': '||额外增长奖金|| = ||0||'}] + \
                                                    this_slip['formulas']

                    elif fslip['TAG'].upper() == 'CVC':
                        this_slip['display_order'] += ['Crestor标准增长金额', 'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.1|| + ||Brilinta标准增长金额|| * ||0.12||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'CVK':
                        this_slip['display_order'] += ['Betaloc ZOK标准增长金额', 'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Betaloc ZOK标准增长金额|| * ||0.12|| + ||Brilinta标准增长金额|| * ||0.12||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'CVX_C':
                        this_slip['display_order'] += ['Crestor标准增长金额', 'Betaloc ZOK标准增长金额', 'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.04|| + ||Betaloc ZOK标准增长金额|| * ||0.04|| + ||Brilinta标准增长金额|| * ||0.12||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'CVX_E':
                        this_slip['display_order'] += ['Crestor标准增长金额', 'Betaloc ZOK标准增长金额', 'Brilinta标准增长金额', 'DM标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.08|| + ||Betaloc ZOK标准增长金额|| * ||0.08|| + ||Brilinta标准增长金额|| * ||0.12|| + ||DM标准增长金额|| * ||0.15||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'DMO':
                        this_slip['display_order'] += ['DM标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||DM标准增长金额|| * ||0.12||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'GIORAL':
                        this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.08||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'GIIV':
                        this_slip['display_order'] += ['NexiumIV+LosecIV标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||NexiumIV+LosecIV标准增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'GIALL_C':
                        this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额', 'NexiumIV+LosecIV标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.08|| + ||NexiumIV+LosecIV标准增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'GIALL_E':
                        this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额', 'NexiumIV+LosecIV标准增长金额',
                                                       'NewCVM标准增长金额', 'EstabilishedBrands标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.18|| + ||NexiumIV+LosecIV标准增长金额|| * ||0.14|| + ||NewCVM标准增长金额|| * ||0.2|| + ||EstabilishedBrands标准增长金额|| * ||0.15||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'RE1':
                        this_slip['display_order'] += ['Pul.Respules标准增长金额', 'Bricanyl N.S.标准增长金额', 'Symbicort标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Pul.Respules标准增长金额|| * ||0.05|| + ||Bricanyl N.S.标准增长金额|| * ||0.05|| + ||Symbicort标准增长金额|| * ||0.18||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'RE2_PB':
                        this_slip['display_order'] += ['Pul.Respules标准增长金额', 'Bricanyl N.S.标准增长金额',
                                                       'Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Pul.Respules标准增长金额|| * ||0.1|| + ||Symbicort 80/160d标准增长金额|| * ||0.16|| + ||Symbicort 320d标准增长金额|| * ||0.18|| + ||Bricanyl N.S.标准增长金额|| * ||0.1||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'RE2_MIX':
                        this_slip['display_order'] += ['Pul.Respules标准增长金额', 'Bricanyl N.S.标准增长金额',
                                                       'Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Pul.Respules标准增长金额|| * ||0.075|| + ||Symbicort 80/160d标准增长金额|| * ||0.18|| + ||Symbicort 320d标准增长金额|| * ||0.20|| + ||Bricanyl N.S.标准增长金额|| * ||0.075||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'RE3_C':
                        if fslip[u'Symbicort 80/160d销量'] + fslip[u'Symbicort 320d销量'] -\
                           fslip[u'Symbicort 80/160d去年销量'] - fslip[u'Symbicort 320d去年销量'] > 0:
                            this_slip['display_order'] += ['Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Symbicort 80/160d标准增长金额|| * ||0.08|| + ||Symbicort 320d标准增长金额|| * ||0.1||'}] + \
                                                    this_slip['formulas']
                        else:
                            this_slip['display_order'] += ['Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额']
                            this_slip['formulas'] = [{'title': '由于Symbicort整体未达标',
                                                      'formula': '||标准增长奖金|| = ||0||'}] + \
                                                    this_slip['formulas']
                    elif fslip['TAG'].upper() == 'RE3_E':
                        if fslip[u'Symbicort 80/160d销量'] + fslip[u'Symbicort 320d销量'] -\
                           fslip[u'Symbicort 80/160d去年销量'] - fslip[u'Symbicort 320d去年销量'] > 0:
                            this_slip['display_order'] += ['Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Symbicort 80/160d标准增长金额|| * ||0.18|| + ||Symbicort 320d标准增长金额|| * ||0.2||'}] + \
                                                    this_slip['formulas']
                        else:
                            this_slip['display_order'] += ['Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额']
                            this_slip['formulas'] = [{'title': '由于Symbicort整体未达标',
                                                      'formula': '||标准增长奖金|| = ||0||'}] + \
                                                    this_slip['formulas']
                    elif fslip['TAG'].upper() == 'CVM_CHC':
                        this_slip['display_order'] += ['Crestor标准增长金额', 'Betaloc ZOK标准增长金额',
                                                       'Brilinta标准增长金额', 'DM标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.05|| + ||Betaloc ZOK标准增长金额|| * ||0.05|| + ||Brilinta标准增长金额|| * ||0.12|| + ||DM标准增长金额|| * ||0.15||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'BCA' or fslip['TAG'] == 'BCAF':
                        this_slip['display_order'] += ['Arimidex标准增长金额', 'Faslodex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Arimidex标准增长金额|| * ||0.04|| + ||Faslodex标准增长金额|| * ||0.04||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'BCF':
                        this_slip['display_order'] += ['Faslodex500mg总盒数', '2017年6-11月平均Faslodex500mg盒数']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||(|| ||Faslodex500mg总盒数|| - ||2017年6-11月平均Faslodex500mg盒数|| ||)|| * ||3250|| * ||0.075||'}] + \
                                                this_slip['formulas']

                    elif fslip['TAG'].upper() == 'BCAZ' or fslip['TAG'].upper() == 'BCZ':
                        this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Arimidex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.055|| + ||Arimidex标准增长金额|| * ||0.055||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'OCMIX':
                        if fslip[u'Zoladex3.6mg销量'.replace('.','_dot_')] + fslip[u'Zoladex10.8mg销量'.replace('.','_dot_')] + fslip[u'Casodex销量'] + fslip[u'Arimidex销量'] + fslip[u'Faslodex销量'] - \
                            (fslip[u'Zoladex3.6mg指标'.replace('.','_dot_')] + fslip[u'Zoladex10.8mg指标'.replace('.','_dot_')] + fslip[u'Casodex指标'] + fslip[u'Arimidex指标'] + fslip[u'Faslodex指标']) * 0.9>0.0:
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额',
                                                           'Arimidex标准增长金额', 'Casodex标准增长金额', 'Faslodex标准增长金额',
                                                           'Iressa标准增长金额', 'Tagrisso标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.08|| + ||Zoladex10.8mg标准增长金额|| * ||0.11|| + ||Arimidex标准增长金额|| * ||0.08|| + ||Casodex标准增长金额|| * ||0.08|| + ||Faslodex标准增长金额|| * ||0.075|| + ||Iressa标准增长金额|| * ||0.04|| + ||Tagrisso标准增长金额|| * ||0.01||'}] + \
                                                    this_slip['formulas']
                        else:

                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额',
                                                           'Arimidex标准增长金额', 'Casodex标准增长金额', 'Faslodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.08|| + ||Zoladex10.8mg标准增长金额|| * ||0.11|| + ||Arimidex标准增长金额|| * ||0.08|| + ||Casodex标准增长金额|| * ||0.08|| + ||Faslodex标准增长金额|| * ||0.075||'}] + \
                                                    this_slip['formulas']
                        # elif fslip['TAG'] == 'OCMIX_E':
                        #     this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Arimidex标准增长金额',
                        #                                    'Casodex标准增长金额', 'Faslodex标准增长金额']
                        #     this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                        #                               'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.065|| + ||Zoladex10.8mg标准增长金额|| * ||0.095|| + ||Arimidex标准增长金额|| * ||0.065|| + ||Casodex标准增长金额|| * ||0.065|| + ||Faslodex标准增长金额|| * ||0.065||'}] + \
                        #                             this_slip['formulas']
                    elif fslip['TAG'].upper() == 'PBG_C':
                        this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Casodex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.04|| + ||Zoladex10.8mg标准增长金额|| * ||0.06|| + ||Casodex标准增长金额|| * ||0.04||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'PBG_E':
                        if fslip[u'Zoladex3.6mg销量'.replace('.','_dot_')] + fslip[u'Zoladex10.8mg销量'.replace('.','_dot_')] + fslip[u'Casodex销量'] + fslip[u'Arimidex销量'] + fslip[u'Faslodex销量'] - \
                            (fslip[u'Zoladex3.6mg指标'.replace('.','_dot_')] + fslip[u'Zoladex10.8mg指标'.replace('.','_dot_')] + fslip[u'Casodex指标'] + fslip[u'Arimidex指标'] + fslip[u'Faslodex指标']) * 0.9>0.0:
                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额',
                                                           'Arimidex标准增长金额', 'Casodex标准增长金额', 'Faslodex标准增长金额',
                                                           'Iressa标准增长金额', 'Tagrisso标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.115|| + ||Zoladex10.8mg标准增长金额|| * ||0.14|| + ||Arimidex标准增长金额|| * ||0.08|| + ||Casodex标准增长金额|| * ||0.115|| + ||Faslodex标准增长金额|| * ||0.075|| + ||Iressa标准增长金额|| * ||0.04|| + ||Tagrisso标准增长金额|| * ||0.01||'}] + \
                                                    this_slip['formulas']
                        else:

                            this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额',
                                                           'Arimidex标准增长金额', 'Casodex标准增长金额', 'Faslodex标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.115|| + ||Zoladex10.8mg标准增长金额|| * ||0.14|| + ||Arimidex标准增长金额|| * ||0.08|| + ||Casodex标准增长金额|| * ||0.115|| + ||Faslodex标准增长金额|| * ||0.075||'}] + \
                                                    this_slip['formulas']
                    elif fslip['TAG'].upper() == 'LCI':
                            this_slip['display_order'] += ['Iressa标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Iressa标准增长金额|| * ||0.06||'}] + \
                                                    this_slip['formulas']
                    elif fslip['TAG'].upper() == 'DMX':
                            this_slip['display_order'] += ['DM标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||DM标准增长金额|| * ||0.13||'}] + \
                                                    this_slip['formulas']
                    elif fslip['TAG'].upper() == 'DMF':
                            this_slip['display_order'] += ['Forxiga销量', '2017年6-11月月均销售金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||(|| ||Forxiga销量|| - ||2017年6-11月月均销售金额|| ||)|| * ||0.28||'}] + \
                                                    this_slip['formulas']
                    elif fslip['TAG'].upper() == 'GMX_CVM':
                        this_slip['display_order'] += ['NexiumOral+LosecOral标准增长金额', 'NexiumIV+LosecIV标准增长金额',
                                                       'NewCVM标准增长金额', 'EstabilishedBrands标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||NexiumOral+LosecOral标准增长金额|| * ||0.18|| + ||NexiumIV+LosecIV标准增长金额|| * ||0.14|| + ||NewCVM标准增长金额|| * ||0.2|| + ||EstabilishedBrands标准增长金额|| * ||0.15||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'GMX_ALL':
                        this_slip['display_order'] += ['ALL标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||ALL标准增长金额|| * ||0.075||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'GMX_EAGLE':
                        this_slip['display_order'] += ['ALL(除Tagrisso)标准增长金额', 'Tagrisso标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||ALL(除Tagrisso)标准增长金额|| * ||0.025|| + ||Tagrisso标准增长金额|| * ||0.02||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'CT':
                        this_slip['display_order'] += ['RIA标准增长金额', 'NewCVM标准增长金额(County)', 'Tagrisso标准增长金额', 'EstabilishedBrands标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||RIA标准增长金额|| * ||0.025|| + ||NewCVM标准增长金额(County)|| * ||0.06|| + ||Tagrisso标准增长金额|| * ||0.02|| + ||EstabilishedBrands标准增长金额|| * ||0.04||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'CT_P2':
                        this_slip['display_order'] += ['RIA标准增长金额', 'NewCVM标准增长金额(County)', 'Tagrisso标准增长金额', 'EstabilishedBrands标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||RIA标准增长金额|| * ||0.04|| + ||NewCVM标准增长金额(County)|| * ||0.09|| + ||Tagrisso标准增长金额|| * ||0.02|| + ||EstabilishedBrands标准增长金额|| * ||0.06||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'].upper() == 'LCIT_C':
                        if fslip[u'Iressa销量'] > fslip[u'Iressa指标'] * 0.6:
                            this_slip['display_order'] += ['Iressa标准增长金额', 'Tagrisso标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Iressa标准增长金额|| * ||0.06|| + ||Tagrisso标准增长金额|| * ||0.02||'}] + \
                                                    this_slip['formulas']
                        else:
                            this_slip['display_order'] += ['Iressa标准增长金额', 'Tagrisso标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Iressa标准增长金额|| * ||0.06||'}] + \
                                                    this_slip['formulas']
                    elif fslip[u'TAG'].upper() == 'LCIT_E':
                        if fslip[u'Iressa销量'] > fslip[u'Iressa指标'] * 0.6:
                            this_slip['display_order'] += ['Iressa标准增长金额', 'Tagrisso标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Iressa标准增长金额|| * ||0.1|| + ||Tagrisso标准增长金额|| * ||0.02||'}] + \
                                                    this_slip['formulas']
                        else:
                            this_slip['display_order'] += ['Iressa标准增长金额', 'Tagrisso标准增长金额']
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                      'formula': '||标准增长奖金|| = ||Iressa标准增长金额|| * ||0.1||'}] + \
                                                    this_slip['formulas']
                    elif fslip[u'TAG'].upper() == 'CU_CHC':
                        this_slip['display_order'] += ['ALL标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||ALL标准增长金额|| * ||0.095||'}] + \
                                                this_slip['formulas']
                    #OCMIX
                    if fslip[u'TAG'] in ('OCMIX',):
                        if fslip[u'第一个策略产品A/T'] < 0.9 and fslip[u'第二个策略产品A/T'] < 0.9:
                            this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9)'
                            this_slip['formulas'][-1]['formula'] += ' * ||0.85||'
                        elif fslip[u'第一个策略产品A/T'] < 0.9 or fslip[u'第二个策略产品A/T'] < 0.9:
                            this_slip['formulas'][-1]['title'] += '(一个策略产品A/T < 0.9)'
                            this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        elif (1.0 > fslip[u'第一个策略产品A/T'] > 0.9) and (fslip[u'第二个策略产品A/T'] > 1.0):
                            this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9且一个策略产品A/T > 1.0)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        elif (1.0 > fslip[u'第二个策略产品A/T'] > 0.9) and (fslip[u'第一个策略产品A/T'] > 1.0):
                            this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9且一个策略产品A/T > 1.0)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        elif fslip[u'第一个策略产品A/T'] > 1.0 and fslip[u'第二个策略产品A/T'] > 1.0:
                            this_slip['formulas'][-1]['title'] += '(两个策略产品A/T > 1.0)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                    if fslip[u'TAG'] in ('PBG_C','PBG_E'):
                        if fslip[u'第一个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        if fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                    if fslip['TAG'] in ('GIALL_C', 'GIALL_E', 'GMX_CVM'):
                        if fslip[u'第一个策略产品A/T'] < 0.8:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                            this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        elif 1.1 > fslip[u'第一个策略产品A/T'] > 1.0:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        elif fslip[u'第一个策略产品A/T'] > 1.1:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.1)'
                            this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                    # 策略产品
                    # if 'H2' in slip_title:
                        if fslip['TAG'] in ('PBG_C','PBG_E'):
                            if fslip[u'第一个策略产品A/T'] < 0.9:
                                    this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.9)'
                                    this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                        if fslip['TAG'] in ('RE2_MIX',):
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                            elif fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                            elif fslip[u'第一个策略产品A/T'] > 1.1:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.1)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.1||'
                        if fslip['TAG'] in ('GIALL_C', 'GIALL_E'):
                            if fslip[u'第一个策略产品A/T'] < 0.8:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                            elif fslip[u'第一个策略产品A/T'] > 1.0:
                                this_slip['formulas'][-1]['title'] += '(策略产品A/T > 1.0)'
                                this_slip['formulas'][-1]['formula'] += ' * ||1.05||'
                        #OCMIX
                        if fslip['TAG'] in ('OCMIX',):
                            if fslip[u'第一个策略产品A/T'] < 0.9 and fslip[u'第二个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(两个策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.85||'
                            if fslip[u'第一个策略产品A/T'] < 0.9 or fslip[u'第二个策略产品A/T'] < 0.9:
                                this_slip['formulas'][-1]['title'] += '(一个策略产品A/T < 0.9)'
                                this_slip['formulas'][-1]['formula'] += ' * ||0.9||'
                    all_slips.append(this_slip)



            if slip_title.startswith('2016年H2BCBH代表增长奖'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': ['员工号', 'TAG', '员工姓名', '在岗月份数', '策略产品A/T',
                                                   '标准增长奖金', '额外增长奖金', '最终增长奖金'],
                                 'formulas': [{'title': 'YTD最终增长奖金',
                                               'formula': '||最终增长奖金|| = ||标准增长奖金|| + ||额外增长奖金||'}]}
                    if fslip['TAG'] == 'CVB':
                        this_slip['display_order'] += ['Brilinta标准增长金额', 'Brilinta额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Brilinta标准增长金额|| * ||0.133||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Brilinta额外增长金额|| * ||0.132||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'CVC':
                        this_slip['display_order'] += ['Crestor标准增长金额', 'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.166|| + ||Brilinta标准增长金额|| * ||0.133||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'CVK':
                        this_slip['display_order'] += ['Betaloc ZOK标准增长金额', 'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Betaloc ZOK标准增长金额|| * ||0.195|| + ||Brilinta标准增长金额|| * ||0.133||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'CVX':
                        this_slip['display_order'] += ['Crestor标准增长金额', 'Betaloc ZOK标准增长金额', 'Brilinta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Crestor标准增长金额|| * ||0.13|| + ||Betaloc ZOK标准增长金额|| * ||0.13|| + ||Brilinta标准增长金额|| * ||0.133||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'DMO':
                        this_slip['display_order'] += ['Onglyza标准增长金额', 'Byetta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                    'formula': '||标准增长奖金|| = ||Onglyza标准增长金额|| * ||0.245|| + ||Byetta标准增长金额|| * ||0.2||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'DMB':
                        this_slip['display_order'] += ['Byetta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Byetta标准增长金额|| * ||0.22||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'DMX':
                        this_slip['display_order'] += ['Onglyza标准增长金额', 'Byetta标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Onglyza标准增长金额|| * ||0.22|| + ||Byetta标准增长金额|| * ||0.2||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'ANA':
                        this_slip['display_order'] += ['Diprivan 20ml标准增长金额', 'Diprivan PFS标准增长金额', 'Naropin标准增长金额',
                                                       'Naropin额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Diprivan 20ml标准增长金额|| * ||0.08|| + ||Diprivan PFS标准增长金额|| * ||0.08|| + ||Naropin标准增长金额|| * ||0.1||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Naropin额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'GIOral':
                        this_slip['display_order'] += ['Nexium Oral标准增长金额', 'Nexium Oral额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Nexium Oral标准增长金额|| * ||0.165||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Nexium Oral额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'GIIV':
                        this_slip['display_order'] += ['Nexium IV标准增长金额', 'Nexium IV额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Nexium IV标准增长金额|| * ||0.115||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Nexium IV额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'GIALL':
                        this_slip['display_order'] += ['Nexium Oral标准增长金额', 'Nexium Oral额外增长金额', 'Nexium IV标准增长金额',
                                                       'Nexium IV额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Nexium Oral标准增长金额|| * ||0.12|| + ||Nexium IV标准增长金额|| * ||0.09||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Nexium Oral额外增长金额|| * ||0.05|| + ||Nexium IV额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'GA':
                        this_slip['display_order'] += ['Diprivan 20ml标准增长金额', 'Diprivan PFS标准增长金额',
                                                       'Naropin标准增长金额', 'Nexium Oral标准增长金额', 'Nexium IV标准增长金额',
                                                       'Naropin额外增长金额', 'Nexium Oral额外增长金额', 'Nexium IV额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Diprivan 20ml标准增长金额|| * ||0.07|| + ||Diprivan PFS标准增长金额|| * ||0.07|| + ||Naropin标准增长金额|| * ||0.08|| + ||Nexium Oral标准增长金额|| * ||0.12|| + ||Nexium IV标准增长金额|| * ||0.07||'},
                                                 {'title': 'YTD额外增长奖金',
                                                  'formula': '||额外增长奖金|| = ||Nexium IV额外增长金额|| * ||0.05|| + ||Nexium Oral额外增长金额|| * ||0.05|| + ||Naropin额外增长金额|| * ||0.05||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'RE1':
                        this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Bricanyl N.S.标准增长金额',
                                                       'Pul.Respules0.5mg标准增长金额', 'Symbicort 80/160d标准增长金额',
                                                       'Pul.Respules0.5mg额外增长金额']
                        # 9月对增长系数做了调整
                        if '2016年7月' in slip_title or '2016年8月' in slip_title:
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                    'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.059|| + ||Bricanyl N.S.标准增长金额|| * ||0.058|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.114|| + ||Symbicort 80/160d标准增长金额|| * ||0.098||'},
                                                    {'title': 'YTD额外增长奖金',
                                                    'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.028||'}] + \
                                                    this_slip['formulas']
                        else:
                            this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                    'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.085|| + ||Bricanyl N.S.标准增长金额|| * ||0.058|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.114|| + ||Symbicort 80/160d标准增长金额|| * ||0.098||'},
                                                    {'title': 'YTD额外增长奖金',
                                                    'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.028||'}] + \
                                                    this_slip['formulas']
                    elif fslip['TAG'] == 'RE3':
                        this_slip['display_order'] += ['Symbicort 80/160d标准增长金额', 'Symbicort 320d标准增长金额',
                                                       'Rhinocort标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Symbicort 80/160d标准增长金额|| * ||0.165|| + ||Symbicort 320d标准增长金额|| * ||0.185|| + ||Rhinocort标准增长金额|| * ||0.07||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'RE2':
                        this_slip['display_order'] += ['Pul.Respules1mg标准增长金额', 'Pul.Respules0.5mg标准增长金额',
                                                       'Rhinocort标准增长金额', 'Symbicort 80/160d标准增长金额',
                                                       'Symbicort 320d标准增长金额', 'Bricanyl N.S.标准增长金额',
                                                       'Pul.Respules0.5mg额外增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                    'formula': '||标准增长奖金|| = ||Pul.Respules1mg标准增长金额|| * ||0.05|| + ||Pul.Respules0.5mg标准增长金额|| * ||0.114|| + ||Rhinocort标准增长金额|| * ||0.07|| + ||Symbicort 80/160d标准增长金额|| * ||0.11|| + ||Symbicort 320d标准增长金额|| * ||0.11|| + ||Bricanyl N.S.标准增长金额|| * ||0.05||'},
                                                    {'title': 'YTD额外增长奖金',
                                                    'formula': '||额外增长奖金|| = ||Pul.Respules0.5mg额外增长金额|| * ||0.028||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'RE-R':
                        this_slip['display_order'] += ['Rhinocort标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Rhinocort标准增长金额|| * ||0.07||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'BCA':
                        this_slip['display_order'] += ['Arimidex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Arimidex标准增长金额|| * ||0.09||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'BCF':
                        this_slip['display_order'] += ['Faslodex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Faslodex标准增长金额|| * ||0.088||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'BCAF':
                        this_slip['display_order'] += ['Arimidex标准增长金额', 'Faslodex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Arimidex标准增长金额|| * ||0.11|| + ||Faslodex标准增长金额|| * ||0.088||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'BCZ':
                        this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.114|| + ||Zoladex10.8mg标准增长金额|| * ||0.114||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'PBG':
                        this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Casodex标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.06|| + ||Zoladex10.8mg标准增长金额|| * ||0.065|| + ||Casodex标准增长金额|| * ||0.06||'}] + \
                                                this_slip['formulas']
                    elif fslip['TAG'] == 'OCMIX':
                        this_slip['display_order'] += ['Zoladex3.6mg标准增长金额', 'Zoladex10.8mg标准增长金额', 'Arimidex标准增长金额',
                                                       'Casodex标准增长金额', 'Faslodex标准增长金额', 'Iressa标准增长金额']
                        this_slip['formulas'] = [{'title': 'YTD标准增长奖金',
                                                  'formula': '||标准增长奖金|| = ||Zoladex3.6mg标准增长金额|| * ||0.06|| + ||Zoladex10.8mg标准增长金额|| * ||0.085|| + ||Arimidex标准增长金额|| * ||0.09|| + ||Casodex标准增长金额|| * ||0.04|| + ||Faslodex标准增长金额|| * ||0.088||'}] + \
                                                this_slip['formulas']
                    else:
                        pass
                    # 检查策略产品A/T
                    if fslip['TAG'] in ('GIALL', 'ANA', 'RE2'):
                        if fslip[u'策略产品A/T'] < 0.8:
                            # this_slip['slip'][u'最终增长奖金'] /= 0.8
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.8)'
                            this_slip['formulas'][-1]['formula'] = '||最终增长奖金|| = ||(|| ||标准增长奖金|| + ||额外增长奖金|| ||)|| * ||0.8||'
                        if fslip[u'策略产品A/T'] >= 1.2:
                            # this_slip['slip'][u'最终增长奖金'] /= 1.2
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T >= 1.2)'
                            this_slip['formulas'][-1][
                                'formula'] = '||最终增长奖金|| = ||(|| ||标准增长奖金|| + ||额外增长奖金|| ||)|| * ||1.2||'
                    if fslip['TAG'] in ('OCMIX', 'PBG'):
                        if fslip[u'策略产品A/T'] < 0.9:
                            this_slip['formulas'][-1]['title'] += '(策略产品A/T < 0.9)'
                            this_slip['formulas'][-1]['formula'] = '||最终增长奖金|| = ||(|| ||标准增长奖金|| + ||额外增长奖金|| ||)|| * ||0.8||'
                    all_slips.append(this_slip)
            # KA
            if slip_title.startswith('KA奖支付-KAM&DKAM'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    this_slip = {'title': '当月%s' % idx,
                                 'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                 'display_order': display_order,
                                 'formulas': [{'title': 'NonTop当月实发',
                                               'formula': '||NonTop当月实发|| = ||总奖金基数|| * ||0.2|| * ||NonTop进药个数A/T系数|| - ||NonTop累计已发||'},
                                              {'title': 'Top1500当月实发',
                                               'formula': '||Top1500当月实发|| = ||总奖金基数|| * ||0.5|| * ||Top1500A/T系数|| - ||Top1500累计已发||'},
                                              {'title': '总控问题奖金',
                                               'formula': '||总控问题奖金|| = ||单月奖金基数|| * ||0.2|| * ||总控问题系数||'},
                                              {'title': '二次议价奖金',
                                               'formula': '||二次议价奖金|| = ||单月奖金基数|| * ||0.1|| * ||二次议价系数||'},
                                              {'title': '当月总奖金',
                                               'formula': '||当月总奖金|| = ||NonTop当月实发|| + ||Top1500当月实发|| + ||总控问题奖金|| + ||二次议价奖金|| + ||Iressa特殊进药奖||' if u'Iressa特殊进药奖' in fslip else '||当月总奖金|| = ||NonTop当月实发|| + ||Top1500当月实发|| + ||总控问题奖金|| + ||二次议价奖金||'}]
                                }
                    all_slips.append(this_slip)
            if slip_title.startswith('KA奖支付-RKAM'):
                idx = 0
                for fslip in final_slips:
                    idx += 1
                    if fslip[u'计算月份'] in ('201601', '201604', '201607', '201610'):
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'NonTop当月实发',
                                                   'formula': '||NonTop当月实发|| = ||(|| ||总奖金基数|| * ||0.2|| * ||NonTop进药个数A/T系数|| - ||NonTop累计已发|| ||)|| / ||3||'},
                                                  {'title': 'Top1500当月实发',
                                                   'formula': '||Top1500当月实发|| = ||(|| ||总奖金基数|| * ||0.5|| * ||Top1500A/T系数|| - ||Top1500累计已发|| ||)|| / ||3||'},
                                                  {'title': '总控问题奖金',
                                                   'formula': '||总控问题奖金|| = ||单月奖金基数|| * ||0.2|| * ||总控问题系数||'},
                                                  {'title': '二次议价奖金',
                                                   'formula': '||二次议价奖金|| = ||单月奖金基数|| * ||0.1|| * ||二次议价系数||'},
                                                  {'title': '当月总奖金',
                                                   'formula': '||当月总奖金|| = ||NonTop当月实发|| + ||Top1500当月实发|| + ||总控问题奖金|| + ||二次议价奖金||'}]
                                    }
                    elif fslip[u'计算月份'] in ('201602', '201605', '201608', '201611'):
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'NonTop当月实发',
                                                   'formula': '||NonTop当月实发|| = ||(|| ||总奖金基数|| * ||0.2|| * ||NonTop进药个数A/T系数|| - ||NonTop累计已发|| ||)|| / ||2||'},
                                                  {'title': 'Top1500当月实发',
                                                   'formula': '||Top1500当月实发|| = ||(|| ||总奖金基数|| * ||0.5|| * ||Top1500A/T系数|| - ||Top1500累计已发|| ||)|| / ||2||'},
                                                  {'title': '总控问题奖金',
                                                   'formula': '||总控问题奖金|| = ||单月奖金基数|| * ||0.2|| * ||总控问题系数||'},
                                                  {'title': '二次议价奖金',
                                                   'formula': '||二次议价奖金|| = ||单月奖金基数|| * ||0.1|| * ||二次议价系数||'},
                                                  {'title': '当月总奖金',
                                                   'formula': '||当月总奖金|| = ||NonTop当月实发|| + ||Top1500当月实发|| + ||总控问题奖金|| + ||二次议价奖金||'}]
                                    }
                    else:
                        this_slip = {'title': '当月%s' % idx,
                                     'slip': {fk.replace('_dot_', '.'): fslip[fk] for fk in fslip},
                                     'display_order': display_order,
                                     'formulas': [{'title': 'NonTop当月实发',
                                                   'formula': '||NonTop当月实发|| = ||总奖金基数|| * ||0.2|| * ||NonTop进药个数A/T系数|| - ||NonTop累计已发||'},
                                                  {'title': 'Top1500当月实发',
                                                   'formula': '||Top1500当月实发|| = ||总奖金基数|| * ||0.5|| * ||Top1500A/T系数|| - ||Top1500累计已发||'},
                                                  {'title': '总控问题奖金',
                                                   'formula': '||总控问题奖金|| = ||单月奖金基数|| * ||0.2|| * ||总控问题系数||'},
                                                  {'title': '二次议价奖金',
                                                   'formula': '||二次议价奖金|| = ||单月奖金基数|| * ||0.1|| * ||二次议价系数||'},
                                                  {'title': '当月总奖金',
                                                   'formula': '||当月总奖金|| = ||NonTop当月实发|| + ||Top1500当月实发|| + ||总控问题奖金|| + ||二次议价奖金||'}]
                                    }
                    all_slips.append(this_slip)
            if not all_slips:
                # 没有特定走公共
                my_slip = db.get_slip(company_name, user_id, calc_id)
                if my_slip and my_slip['result']:
                    slips = []
                    for sr in my_slip['result']:
                        slips.append({'display_order': my_slip['display_order'],
                                      'slip': {k: str(sr[k]) for k in my_slip['display_order']}})
                    my_appeal = db._find_one_in_org('Appeal', {'user_id': user_id, 'calculation': calc_id},
                                                    company_name)
                    if my_appeal:
                        return jsonify(success=True, title=my_slip['title'], slips=slips,
                                       comment=my_appeal.get('comment', ''), reply=my_appeal.get('reply', ''))
                    else:
                        return jsonify(success=True, title=my_slip['title'], slips=slips, comment='', reply='')
        else:
            all_slips = []
        return jsonify(success=True,
                       # formulas=formulas,
                       title=_clean_az_slip_title(slip_title),
                       slips=all_slips,
                       related_slips=[],
                       # [json.loads(slip) for slip in cache.get_list('%s:result.related:%s' % (company_name, calc_id))],
                       # display_order=display_order
                       )

def _get_calculation_result(calc_id, company_name, form_data, replace_data={}, env=const.ENV_PRODUCTION):
    """
    获取临时计算结果
    :param calc_id: 计算id，以一个现存计算作为参数模板
    :type calc_id: str
    :param company_name: 公司名
    :type company_name: str
    :param form_data: 来自页面的数据或者用于替换的数据，只有和数据源中列名相同的值才可能起效。必须提供计算单位字段，格式{label:value}
    :type form_data: dict
    :param replace_data: 用于替换某个计算源数据或者计算结果数据，格式{version_id:[lines],result_id:[lines]}
    :param env: 数据库类型
    :return:
    """
    # 获取计算模板并处理为模算模板
    calc_template = db._find_one_in_org('Calculation',{'_id': ObjectId(calc_id)},company_name)
    if not calc_template:
        return u"无法获取计算数据"
    calc_template['_id'] = 'n/a'
    calc_template['category'] = 'sim'
    calc_template['data_filter'] = {}
    kpi_map_data = calc_template['kpi_map'].get('data')
    kpi_map_result = calc_template['kpi_map'].get('result')

    # 计算数据
    sim_data = {}
    sim_result = {}

    # 获取对应方案以获取计算单位
    policy_id = calc_template['policy']
    sim_policy = db._find_one_in_org('Policy', {'_id': ObjectId(policy_id)}, company_name)
    # 计算单位
    calc_unit = sim_policy['unit'].split(',') # str list
    # 验证提供数据是否包含全部计算单位
    if not set(calc_unit).intersection(set(form_data.keys())) == set(calc_unit):
        return u"请提供全部计算单位数据"

    # 获取并处理架构数据
    if calc_template['hierarchy_source']['source'] == 'data':
        # 如果架构数据是源数据
        version_id = calc_template['hierarchy_source']['id']
        if replace_data.has_key(version_id):
            hierarchy_data = replace_data[version_id]
        else:
            r = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_VERSION_INFO, version_id),company_name, env))
            if not (r.status_code == 200 and r.json().get('success', False)):
                return u"无法获得数据版本信息:%s" % version_id
            file_file_id = r.json()['data']['file_file_id']
            fitler = 'and'.join([" \"%s\"='%s' " % (kpi_map_data[version_id][unit], form_data[unit]) for unit in calc_unit])
            # TODO 按某种配置规律可以读取多行架构数据
            sql = "select * from \"%s\" where%slimit 1" % (file_file_id, fitler)
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return u"无法获取源数据：%s" % version_id
            hierarchy_data = r.json()['data']
            # 处理架构数据,已可以处理多行数据
            for h_data in hierarchy_data:
                for key in set(kpi_map_data[version_id].values()).intersection(set(form_data.keys())):
                    h_data[kpi_map_data[version_id][key]] = form_data[key]
        sim_data[version_id] = hierarchy_data
    else:
        # 如果架构数据是其他计算结果
        result_id = calc_template['hierarchy_source']['id']
        if replace_data.has_key(result_id):
            hierarchy_data = replace_data[result_id]
        else:
            rslt_id = str(db.get_calc_result_id(result_id, calc_template['owner']))
            # query = {kpi_map_result[rslt_id][unit]: form_data[unit] for unit in calc_unit if kpi_map_result[rslt_id][unit]}
            # r = db.get_result_by_id_with_query(rslt_id, calc_template['owner'],query, only_one=False)
            query = {kpi_map_result[rslt_id][unit]: form_data[unit] for unit in calc_unit}
            r = db.get_result_by_id_with_query(rslt_id, calc_template['owner'], query, only_one=True)
            if not r:
                return "无法获取其他计算结果数据：%s" % result_id
            for r_data in r['result']:
                for key in set(kpi_map_result[rslt_id].values()).intersection(set(form_data.keys())):
                    r_data[kpi_map_result[rslt_id][key]] = form_data[key]
            hierarchy_data = r['result']
        sim_result[result_id] = hierarchy_data

    # 获取并处理一般数据
    normal_data = {}
    for version_id in calc_template['data_version']:
        # 跳过已经处理的架构数据
        if calc_template['hierarchy_source']['id'] == version_id:
            continue
        # 如果提供了数据，则不再从库中查询
        if replace_data.has_key(version_id):
            normal_data[version_id] = replace_data[version_id]
        # 按架构数据中计算单位的值取数据
        else:
            r = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_VERSION_INFO, version_id), company_name, env))
            if not (r.status_code == 200 and r.json().get('success', False)):
                return "无法获得数据版本信息:%s" % version_id
            file_file_id = r.json()['data']['file_file_id']
            fitler = 'and'.join([" \"%s\"='%s' " % (kpi_map_data[version_id][unit], hierarchy_data[0][unit]) for unit in calc_unit
                                 if kpi_map_data[version_id][unit]])
            sql = "select * from \"%s\" where%s" % (file_file_id, fitler)
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return "无法获取数据:%s" % version_id
            tmp_data = r.json()['data']
            # 处理一般数据
            for t_data in tmp_data:
                for key in set(kpi_map_data[version_id].values()).intersection(set(form_data.keys())):
                    t_data[kpi_map_data[version_id][key]] = form_data[key]
            normal_data[version_id] = tmp_data
    sim_data.update(normal_data)

    # 获取处理其他计算结果
    for result_id in calc_template['result_source']:
        # 跳过已经处理的架构数据
        if calc_template['hierarchy_source']['id'] == result_id:
            continue
        # 如果提供了数据，则不再从库中查询
        if replace_data.has_key(result_id):
            sim_result[result_id] = replace_data[result_id]
        # 按架构数据中计算单位的值取数据
        # 将计算ID转换为结果id
        else:
            rslt_id = str(db.get_calc_result_id(result_id, calc_template['owner']))
            query = {kpi_map_result[rslt_id][unit]: hierarchy_data[0][unit] for unit in calc_unit if kpi_map_result[rslt_id][unit]}
            r = db.get_result_by_id_with_query(rslt_id, calc_template['owner'],query, only_one=False)
            for r_data in r['result']:
                for key in set(kpi_map_result[rslt_id].values()).intersection(set(form_data.keys())):
                    r_data[kpi_map_result[rslt_id][key]] = form_data[key]
            sim_result[result_id] = r['result']

    # 组装计算数据并返回计算执行结果
    sim_args = {'sim_meta': calc_template, const.TASK_ARG_COMPANYNAME: company_name}
    if sim_result:
        sim_args['sim_result'] = sim_result
    if sim_data:
        sim_args['sim_data'] = sim_data
    return execute_simulation(sim_args)

# 获取制定数据分类内选定版本的数据在数据库中的序号名和表名
def _get_data_file_version_id_and_file_id(data_cla, company, version_ids,quarter=None, env=const.ENV_PRODUCTION):
    api_url = lib.data_api(cfg.DATA_API_CATEGORY_VERSIONS,
                           company,
                           env)
    r = requests.get(api_url, verify=False)
    quarters = {}
    version_id = ''
    if r.status_code == 200 and r.json().get('success', False):
        for ctg in r.json().get('data', []):
            if not ctg['name'] == data_cla:
                continue
            else:
                for tbl in ctg['versions']:
                    quarters[tbl['name']] = tbl['id'], tbl['file_file_id']
                    # 使用计算中旧的version_id来对应新的数据的file_fil_id
                    if str(tbl['id']) in version_ids:
                        version_id = tbl['id']
        # 返回指定季节的序号名和表名
        # 未指定季节时返回最新季节的表名
        quarter = quarter if quarter is not None else sorted(quarters.keys(), reverse=True)[0]
        version_id = version_id if version_id else quarters[quarter][0]
        return version_id, quarters[quarter][1]
    else:
        print r.json()['message']
        return '',''

# 获取制定数据分类内选定版本的数据在数据库中的表名
def _get_data_file_file_id(data_cla, company, table_name=None, env=const.ENV_PRODUCTION):
    api_url =  lib.data_api(cfg.DATA_API_CATEGORY_VERSIONS,
                               company,
                               env)
    r = requests.get(api_url, verify=False)
    quarters = {}
    if r.status_code == 200 and r.json().get('success', False):
        for ctg in r.json().get('data', []):
            if not ctg['name'] == data_cla:
                continue
            else:
                for tbl in ctg['versions']:
                    quarters[tbl['name']] = tbl['file_file_id']
                    if tbl['name'] == table_name:
                        # 返回指定季节的表名
                        return tbl['file_file_id']
        if quarters:
            # 未指定季节时返回最新季节的表名
            return quarters[sorted(quarters.keys(),reverse=True)[0]]
        else:
            return ''
    else:
        print r.json()['message']
        return ''

# 模拟计算器
def _get_sim_source_table(team, company):
    # need config
    # 注意：上传新数据后要到calculation_form里查看新的file_file_id
    if company == 'az':
        # if team.upper() == 'BCBH':
        #     return '1470675941836628'
        # if team.upper() == 'COUNTY':
        #     return '1470676055106829'
        # return ''
        api_url = lib.data_api(cfg.DATA_API_CATEGORY_VERSIONS,
                               company,
                               const.ENV_PRODUCTION)
        r = requests.get(api_url, verify=False)
        if r.status_code == 200 and r.json().get('success', False):
            for ctg in r.json().get('data', []):
                if ctg['name'] not in ('模算数据',):
                    continue
                for tbl in ctg['versions']:
                    # 指标是每月维护的，在此处加入
                    # if tbl['name'] in ['2016年H2指标', '2017年H1指标']:
                        # if (ctg['name'] == '2017年BCBH销售数据' and team.upper() == 'BCBH') or (ctg['name'] == 'County销售数据' and team.upper() == 'COUNTY'):
                    # if (tbl['name'] == '2017年H1指标-BCBH' and team.upper() == 'BCBH') or (tbl['name'] == '2017年H1指标-County' and team.upper() == 'COUNTY'):
                    #     return tbl['file_file_id']
                    if (tbl['name'] == '2018年BCBH' and team.upper() == 'BCBH') or (tbl['name'] == '2018年1月County' and team.upper() == 'COUNTY'):
                        return tbl['file_file_id']
            return ''
        else:
            print r.json()['message']
            return ''
    elif company == 'hisunpfizer':
        use_quarter = ''
        # 先从配置表读取数据时间
        api_url = lib.data_api(cfg.DATA_API_CATEGORY_VERSIONS,
                               company,
                               const.ENV_PRODUCTION)
        r = requests.get(api_url, verify=False)
        if r.status_code == 200 and r.json().get('success', False):
            for ctg in r.json().get('data', []):
                if ctg['name'] == 'QUARTER':
                    for tbl in ctg['versions']:
                        if tbl['name'] == 'quarter_data':
                            sql = "select * from \"%s\" limit 1" % tbl['file_file_id']
                            api_url2 = lib.data_api(cfg.DATA_API_RUN_SQL, company, const.ENV_PRODUCTION)
                            r2 = requests.post(api_url2, data={'sql': sql})
                            if not (r2.status_code == 200 and r2.json().get('success', False)):
                                print 'Failed to get data time. Use default value.'
                                use_quarter = lib.now_quarter()
                            else:
                                time_data = r2.json().get('data', [])
                                if time_data:
                                    use_quarter = time_data[0].get('quarter', lib.now_quarter()).upper()
                                else:
                                    print 'Empty data time. Use default value.'
                                    use_quarter = lib.now_quarter()
                            break
                    break
            if not use_quarter:
                print 'Did not find data time. Use default value.'
                use_quarter = lib.now_quarter()
        else:
            print r.json()['message']
            use_quarter = lib.now_quarter()
        # 用取到的配置时间去找数据表
        api_url = lib.data_api(cfg.DATA_API_CATEGORY_VERSIONS,
                               company,
                               const.ENV_PRODUCTION)
        r = requests.get(api_url, verify=False)
        if r.status_code == 200 and r.json().get('success', False):
            for ctg in r.json().get('data', []):
                if not ctg['name'] == 'HAIZHENG':
                    continue
                for tbl in ctg['versions']:
                    if tbl['name'] == use_quarter:
                        return tbl['file_file_id'], use_quarter
            return '', ''
        else:
            print r.json()['message']
            return '', ''
    elif company == 'bayer':
        api_url = lib.data_api(cfg.DATA_API_CATEGORY_VERSIONS,
                               company,
                               const.ENV_PRODUCTION)
        r = requests.get(api_url, verify=False)
        if r.status_code == 200 and r.json().get('success', False):
            for ctg in r.json().get('data', []):
                if not ctg['name'] == 'BiddingDemo':
                    continue
                for tbl in ctg['versions']:
                    if tbl['name'] == 'MR':
                        return tbl['file_file_id']
            return ''
        else:
            print r.json()['message']
            return ''
    else:
        return ''


def _ym2title(ym, postfix='YTD'):
    return '%s年%s月%s' % (ym[:4], int(ym[-2:]), postfix)


# Step1:获取可模拟的方案(部分客户可能不需要)
@app.route('/api/simable')
def api_get_simable_policies():
    # 验证通过SSO登录的用户的JWT
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    if company_name == 'az':
        uinfo = db.get_sim_hierarchy(user_id.upper(), company_name)
        if not uinfo:
            return jsonify(success=False, message='找不到架构数据。')
        my_tags = []
        months = {}
        if uinfo['level'].upper() == 'REP':
            # 2017 H1
            # 指定模拟计算使用的原始数据。这里要让用户选择TAG，所以根据员工号搜索数据即可。
            sql = "select \"USER_CODE\",\"TAG_NAME\",\"YM\" from \"%s\" where \"USER_CODE\"='%s' order by \"YM\"" % \
                  (_get_sim_source_table(uinfo['team'].upper(), company_name),  # 获取使用的数据表
                   uinfo.get('user_code', '').upper())
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='获取数据失败：%s' % r.json().get('message', '未知错误。'))
            # need config
            my_data = r.json().get('data', [])
            for md in my_data:
                if md['TAG_NAME']:
                    if md['TAG_NAME'] not in my_tags:
                        my_tags.append(md['TAG_NAME'])
                    if md['TAG_NAME'] not in months:
                        months[md['TAG_NAME']] = []
                    # if md['YM'] not in months[md['TAG_NAME']]:
                    #     if md['YM'] in ('201801', '201802', '201803', '201804', '201805', '201806'):
                    months[md['TAG_NAME']].append({'value': md['YM'], 'title': _ym2title(md['YM'])})
            if uinfo['team'].upper() == 'BCBH':
                # sim_templ_achi = {'_id': '59ae589de9c6a300349edc53', 'title': '2017年BCBH代表达成贡献奖'} # 2017年BCBH代表达成贡献奖-H2模算
                # sim_templ_incr = {'_id': '59ae58a5e9c6a300349edc84', 'title': '2017年BCBH代表增长奖'} # 2017年BCBH代表增长奖-H2模算
                sim_templ_achi = {'_id': '5aa744c2139976000ddf106e', 'title': '2018年BCBH&County代表达成贡献奖'} # 2018年BCBH&County代表达成贡献奖-模拟
                sim_templ_incr = {'_id': '5aa74591139976002c3c7aee', 'title': '2018年BCBH&County代表增长奖'} # 2018年BCBH&County代表增长奖-模拟

                # LC未加入
                tag_list = ['BCA', 'BCAF', 'BCAZ', 'BCF', 'BCZ', 'CU_CHC', 'CVB', 'CVC', 'CVK', 'CVM_CHC', 'CVX_C',
                            'CVX_E', 'DMF', 'DMO', 'DMX', 'GIALL_C', 'GIALL_E', 'GIIV', 'GIOral', 'GMX_ALL', 'GMX_CVM',
                            'GMX_EAGLE', 'LCI', 'LCIT', 'LCIT_1', 'LCIT_2', 'LCIT_C', 'LCIT_E', 'LCI_1', 'LCI_2', 'LCT',
                            'OCMIX', 'PBG_C', 'PBG_E', 'RE1', 'RE2_Mix', 'RE2_PB', 'RE3_C', 'RE3_E']

                simable = {t:[sim_templ_achi, sim_templ_incr] for t in tag_list}
            # TODO County
            elif uinfo['team'].upper() == 'COUNTY':
                # simable = {'CT': [{'_id': '58abf09628112c000ae0b8d2', 'title': '2017年County代表销售绩效奖-模算'}]}
                sim_templ_achi = {'_id': '5aa744c2139976000ddf106e', 'title': '2018年BCBH&County代表达成贡献奖'} # 2018年BCBH&County代表达成贡献奖-模拟
                sim_templ_incr = {'_id': '5aa74591139976002c3c7aee', 'title': '2018年BCBH&County代表增长奖'} # 2018年BCBH&County代表增长奖-模拟
                simable = {'CT': [sim_templ_achi, sim_templ_incr]}
            else:
                return jsonify(success=False, message='该团队尚未支持模拟计算：%s' % uinfo['team'].upper())
            uinfo['_id'] = str(uinfo['_id'])
            return jsonify(success=True, policies=simable, user_info=uinfo, tags=my_tags, months=months)
            # TODO 冗余代码请在2017设计完成后删除
            # # 指定模拟计算使用的原始数据。这里要让用户选择TAG，所以根据员工号搜索数据即可。
            # sql = "select \"USER_CODE\",\"TAG_NAME\",\"YM\" from \"%s\" where \"USER_CODE\"='%s' order by \"YM\"" % \
            #       (_get_sim_source_table(uinfo['team'].upper(), company_name),  # 获取使用的数据表
            #        uinfo.get('user_code', '').upper())
            # api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
            # r = requests.post(api_url, data={'sql': sql})
            # if not (r.status_code == 200 and r.json().get('success', False)):
            #     return jsonify(success=False, message='获取数据失败：%s' % r.json().get('message', '未知错误。'))
            # my_data = r.json().get('data', [])
            # # need config
            # for md in my_data:
            #     if md['TAG_NAME']:
            #         if md['TAG_NAME'] not in my_tags:
            #             my_tags.append(md['TAG_NAME'])
            #         if md['TAG_NAME'] not in months:
            #             months[md['TAG_NAME']] = []
            #         if md['YM'] not in months[md['TAG_NAME']]:
            #             if md['YM'] in ('201601', '201602', '201603', '201604', '201605', '201606',
            #                             '201607', '201608', '201609', '201610', '201611', '201612'):
            #                 months[md['TAG_NAME']].append({'value': md['YM'], 'title': _ym2title(md['YM'])})
            # if uinfo['team'].upper() == 'BCBH':
            #     sim_templ = [{'_id': '57a8cd3cc558f5000aac3f17', 'title': '2016年H2BCBH代表达成贡献奖'},
            #                  {'_id': '57a8d32dc558f500316898a2', 'title': '2016年H2BCBH代表增长奖'}]
            #     simable = {'CVC': sim_templ,
            #                'CVK': sim_templ,
            #                'CVX': sim_templ,
            #                'CVB': sim_templ,
            #                'DMO': sim_templ,
            #                'DMB': sim_templ,
            #                'DMX': sim_templ,
            #                'ANA': sim_templ,
            #                'GIOral': sim_templ,
            #                'GIIV': sim_templ,
            #                'GIALL': sim_templ,
            #                'GA': sim_templ,
            #                'RE1': sim_templ,
            #                'RE2': sim_templ,
            #                'RE3': sim_templ,
            #                'RE-R': sim_templ,
            #                'BCA': sim_templ,
            #             #    'BCF': sim_templ,
            #                'BCAF': sim_templ,
            #                'BCZ': sim_templ,
            #                'PBG': sim_templ,
            #                'OCMIX': sim_templ,
            #             #    'LC': sim_templ,
            #                }
            # elif uinfo['team'].upper() == 'COUNTY':
            #     simable = {'CT': [{'_id': '573d588f447de7000bf259c2', 'title': '2016年County代表销售绩效奖'}]}
            # else:
            #     return jsonify(success=False, message='该团队尚未支持模拟计算：%s' % uinfo['team'].upper())
            # uinfo['_id'] = str(uinfo['_id'])
            # return jsonify(success=True, policies=simable, user_info=uinfo, tags=my_tags, months=months)
        else:
            return jsonify(success=False, message='该职位尚未支持模拟计算：%s' % uinfo['level'].upper())
    elif company_name == 'bayer':
        return jsonify( success=True, policies={'BA':[{'_id':'57e1e455ba0624000cfdf6e8', 'title': '2016年Q1BHP销售达成奖-ForBiddingDemo'}]},
                        user_info={'employee': [user_id], 'level': 'MR', 'team': 'BHP', 'name':'MMM', 'tag': 'BA'},
                        tags=['BA'],
                        months={'BA': [{'value': '2016Q1', 'title': '2016年Q1'}]})
    elif company_name == 'kaniontest':
        user_info = {
            'name': '唐莉莉',
            'user_code': 'TLL1801',
            'level': 'REP',
            'bu': '主品种'
        }
        sim_policies = [
            {
                "_id": "5b711d717409a3000c7e1ba6",
                "title": "二季度兑现考核",
                "bu": ["主品种"],
                "level": ["REP"]
            }]
        user_data = {
            "name": user_info['name'],
            "user_id": user_info['user_code'],
            "title": user_info['level'],
            "department": user_info['bu']
        }
        result_data = []
        for sim_policy in sim_policies:
            if user_info['bu'] in sim_policy['bu'] and user_info['level'] in sim_policy['level']:
                result_data.append({'_id':sim_policy['_id'], 'title':sim_policy['title']})
        return jsonify(success=True, policies=result_data, user_info=user_data)
    elif company_name == 'gvtest':
        # 绿谷测试环境
        user_info = db.get_sim_hierarchy(user_id, company_name)
        sim_policies = [
            {
                "_id": "5b70ec1a3119a00081b41cec",
                "title": "2018-伟素-省区&销售经理季度提成奖",
                "bu": ["伟素"],
                "level": ["省区经理/销售经理"]
            }]
        user_data = {
            "name": user_info['name'],
            "user_id": user_info['user_code'],
            "title": user_info['level'],
            "department": user_info['bu']
        }
        result_data = []

        for sim_policy in sim_policies:
            if user_info['bu'] in sim_policy['bu'] and user_info['level'] in sim_policy['level']:
                result_data.append({'_id':sim_policy['_id'], 'title':sim_policy['title']})
        return jsonify(success=True, policies=result_data, user_info=user_data)
    elif company_name == 'greenvalley':
        user_info = db.get_sim_hierarchy(user_id, company_name)
        sim_policies = [
            {
                "_id": "5aa8d518033bf50022b3b9dc",
                "title": "2018-自营-医学信息沟通专员(县域)",
                "bu": ["丹酚"],
                "level": ["医学信息沟通专员(县域)"]
            },
            {
                "_id": "5aa8e20c033bf5002c38b797",
                "title": "2018-自营-区域经理",
                "bu": ["丹酚"],
                "level": ["区域经理"]
            },
            {
                "_id": "5ab232f9ef90fc00317e2e85",
                "title": "2018-招商-招商经理/主管",
                "bu": ["丹酚"],
                "level": ["招商经理/主管"]
            },
            {
                "_id": "5ab23ca8ef90fc00317e2e97",
                "title": "2018-民营-终端招商经理",
                "bu": ["丹酚"],
                "level": ["终端招商经理"]
            },
            {
                "_id": "5ab24b4fef90fc00367909c3",
                "title": "2018-销售总监",
                "bu": ["丹酚"],
                "level": ["SD"]
            },
            {
                "_id": "5ad6e8287bdddb005efd905d",
                "title": "2018-招商-李毅",
                "bu": ["丹酚"],
                "level": ["李毅"]
            },
            {
                "_id": "5ae1efaed32066000c6ba115",
                "title": "2018-伟素-总监",
                "bu": ["伟素"],
                "level": ["总监"]
            },
            {
                "_id": "5ae1f39fd32066000d1f9e22",
                "title": "2018-伟素-省区&销售经理季度提成奖",
                "bu": ["伟素"],
                "level": ["省区经理/销售经理"]
            },
            {
                "_id": "5ae3f8b8b577b4000aa921f6",
                "title": "2018-招商-招商福建经理/主管",
                "bu": ["丹酚"],
                "level": ["福建招商"]
            },
            {
                "_id": "5aeaaefaa5b5cc000990383c",
                "title": "2018-自营-医学信息沟通专员",
                "bu": ["丹酚"],
                "level": ["医学信息沟通专员"]
            },
            {
                "_id": "5aeaaffca5b5cc003622c57f",
                "title": "2018-伟素-大区经理季度达成奖",
                "bu": ["伟素"],
                "level": ["大区经理"]
            },
            {
                "_id": "5b1dd908fa5f660022942024",
                "title": "2018-伟素-副总监季度提成奖",
                "bu": ["伟素"],
                "level": ["副总监"]
            },
            {
                "_id": "5ab24056ef90fc00317e2e9e",
                "title": "2018-民营&招商-大区(副)经理",
                "bu": ["丹酚"],
                "level": ["大区(副)经理"]
            },
            {
                "_id": "5ab22b66ef90fc00277da84b",
                "title": "2018-自营-大区经理",
                "bu": ["丹酚"],
                "level": ["自营大区经理"]
            }
        ]
        user_data = {
            "name": user_info['name'],
            "user_id": user_info['user_code'],
            "title": user_info['level'],
            "department": user_info['bu']
        }
        result_data = []

        for sim_policy in sim_policies:
            if user_info['bu'] in sim_policy['bu'] and user_info['level'] in sim_policy['level']:
                result_data.append({'_id':sim_policy['_id'], 'title':sim_policy['title']})
        return jsonify(success=True, policies=result_data, user_info=user_data)
    else:
        return jsonify(success=False, message='该组织尚未支持模拟计算方案的选择。')


def _get_sim_data(policy_id, user_info, company, month):
    policy = db._find_one_in_org('Policy', {'_id': ObjectId(policy_id)}, company)
    if not policy:
        return [], '找不到指定的奖金政策：%s' % policy_id
    if company == 'az':
        tag = user_info.get('tag', '')
        # need config
        if False and policy_id == '573eac648398a20009260940':  # 2016年Q2CV代表达成贡献奖
            # 根据计算的方案选择使用的数据（file_file_id即表名）
            months = []
            for m in range(201604, 201607):
                if int(month) >= m:
                    months.append(str(m))
            sql = "select * from \"%s\" where \"USER_CODE\"='%s' and \"TAG_NAME\"='%s' and \"YM\" in ('%s') order by \"YM\"" % \
                  (_get_sim_source_table('BCBH', company), user_info.get('user_code', '').upper(), tag, '\',\''.join(months))
        elif policy_id == '57a8cd3cc558f5000aac3f17':  # 2016年H2BCBH代表达成贡献奖
            # 根据计算的方案选择使用的数据（file_file_id即表名）
            months = []
            for m in range(201607, 201613):
                if int(month) >= m:
                    months.append(str(m))
            sql = "select * from \"%s\" where \"USER_CODE\"='%s' and \"TAG_NAME\"='%s' and \"YM\" in ('%s') order by \"YM\"" % \
                  (_get_sim_source_table('BCBH', company), user_info.get('user_code', '').upper(), tag, '\',\''.join(months))
        elif policy_id == '57a8d32dc558f500316898a2':  # 2016年H2BCBH代表增长奖
            # 根据计算的方案选择使用的数据（file_file_id即表名）
            months = []
            month_range = range(201607, 201613)
            for m in month_range:
                if int(month) >= m:
                    months.append(str(m))
            sql = "select * from \"%s\" where \"USER_CODE\"='%s' and \"TAG_NAME\"='%s' and \"YM\" in ('%s') order by \"YM\"" % \
                  (_get_sim_source_table('BCBH', company), user_info.get('user_code', '').upper(), tag, '\',\''.join(months))
        elif policy_id == '573d588f447de7000bf259c2':  # 2016年County代表销售绩效奖
            # 根据计算的方案选择使用的数据（file_file_id即表名）
            months = []
            for m in range(201607, 201613):
                if int(month) >= m:
                    months.append(str(m))
            sql = "select * from \"%s\" where \"USER_CODE\"='%s' and \"TAG_NAME\"='%s' and \"YM\" in ('%s') order by \"YM\"" % \
                  (_get_sim_source_table('COUNTY', company), user_info.get('user_code', '').upper(), tag, '\',\''.join(months))
        elif policy_id == '59ae589de9c6a300349edc53':  # 2017年BCBH代表达成贡献奖-模算
            # 根据计算的方案选择使用的数据（file_file_id即表名）
            months = []
            for m in range(201701, 201713):
                if int(month) >= m:
                    months.append(str(m))
            sql = "select * from \"%s\" where \"USER_CODE\"='%s' and \"TAG_NAME\"='%s' and \"YM\" in ('%s') order by \"YM\"" % \
                  (_get_sim_source_table('BCBH', company), user_info.get('user_code', '').upper(), tag, '\',\''.join(months))
        elif policy_id == '59ae58a5e9c6a300349edc84':  # 2017年BCBH代表增长奖-模算
            # 根据计算的方案选择使用的数据（file_file_id即表名）
            months = []
            for m in range(201701, 201713):
                if int(month) >= m:
                    months.append(str(m))
            sql = "select * from \"%s\" where \"USER_CODE\"='%s' and \"TAG_NAME\"='%s' and \"YM\" in ('%s') order by \"YM\"" % \
                  (_get_sim_source_table('BCBH', company), user_info.get('user_code', '').upper(), tag, '\',\''.join(months))
        elif policy_id == '58abf09628112c000ae0b8d2':  # 2017年County代表销售绩效奖-模算
            # 根据计算的方案选择使用的数据（file_file_id即表名）
            months = []
            for m in range(201701, 201713):
                if int(month) >= m:
                    months.append(str(m))
            sql = "select * from \"%s\" where \"USER_CODE\"='%s' and \"TAG_NAME\"='%s' and \"YM\" in ('%s') order by \"YM\"" % \
                  (_get_sim_source_table('COUNTY', company), user_info.get('user_code', '').upper(), tag, '\',\''.join(months))
        elif policy_id == '5aa744c2139976000ddf106e': # 2018达成奖模拟
            # 根据计算的方案选择使用的数据（file_file_id即表名）
            months = []
            for m in range(201801, 201813):
                if int(month) >= m:
                    months.append(str(m))
            sql = "select * from \"%s\" where \"USER_CODE\"='%s' and \"TAG_NAME\"='%s' and \"YM\" in ('%s') order by \"YM\"" % \
                  (_get_sim_source_table(user_info['team'].upper(), company), user_info.get('user_code', '').upper(), tag, '\',\''.join(months))
        elif policy_id == '5aa74591139976002c3c7aee': # 2018增长奖模拟
            # 根据计算的方案选择使用的数据（file_file_id即表名）
            months = []
            for m in range(201801, 201813):
                if int(month) >= m:
                    months.append(str(m))
            sql = "select * from \"%s\" where \"USER_CODE\"='%s' and \"TAG_NAME\"='%s' and \"YM\" in ('%s') order by \"YM\"" % \
                  (_get_sim_source_table(user_info['team'].upper(), company), user_info.get('user_code', '').upper(), tag, '\',\''.join(months))
        else:
            return [], '该奖金政策尚未支持模拟计算：%s' % policy['title']
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': sql})
        if r.status_code == 200 and r.json().get('success', False):
            got_data = r.json().get('data', [])
            return got_data, '' if got_data else '找不到数据字段。'
        else:
            return [], '获取数据失败：%s' % r.json().get('message', '未知错误。')
    else:
        return [], '该组织尚未支持模拟计算：%s' % company


# Step2:获取输入字段
@app.route('/api/sim/<tag>/<policy_id>/<month>')
def api_get_sim_form(tag, policy_id, month):
    # 验证通过SSO登录的用户的JWT
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    if company_name == 'az':
        uinfo = db.get_sim_hierarchy(user_id.upper(), company_name)
        if not uinfo:
            return jsonify(success=False, message='找不到架构数据。')
        uinfo['tag'] = tag
        data = {'cmn': [], 'data': {}}
        policy_to_sim = policy_id
        policy = db._find_one_in_org('Policy', {'_id': ObjectId(policy_to_sim)}, company_name)
        if not policy:
            return jsonify(success=False, message='找不到指定的奖金政策：%s' % policy_to_sim)
        data['cmn'].append({'label': '试算方案', 'value': policy['title'], 'type': 'static'})
        # # need config
        # # 如果试算的方案依赖于数据预处理，那么要转为计算预处理方案
        # if policy_to_sim == '573eac648398a20009260940':  # 2016年Q2CV代表达成贡献奖
        #     policy_to_sim = '573ea1f97417ed000d9d9ba3'  # 2016年Q2CV代表产品捆绑
        # policy = db._find_one_in_org('Policy', {'_id': ObjectId(policy_to_sim)}, company_name)
        # if not policy:
        #     return jsonify(success=False, message='找不到指定的奖金政策：%s' % policy_to_sim)
        # need config
        with open('incentivepower/conf/%s_sim_form.json' % company_name, 'rb') as sim_form_file:
            sim_form = json.load(sim_form_file)
        if False and policy_to_sim == '573eac648398a20009260940':  # 2016年Q2CV代表达成贡献奖
            # 读取试算方案所需的所有源数据。这实际上是确定计算单位的过程。
            sim_data, msg = _get_sim_data(policy_to_sim, uinfo, company_name, month)
            if sim_data:
                rd = sim_data
                data['cmn'].append({'label': '试算月份', 'value': month, 'type': 'static'})
                data['cmn'].append({'label': '员工姓名', 'value': rd[0]['USER_NAME'], 'type': 'static'})
                data['cmn'].append({'label': '员工号', 'value': rd[0]['USER_CODE'], 'type': 'static'})
                data['cmn'].append({'label': 'TAG', 'value': rd[-1]['TAG_NAME'], 'type': 'static'})
                # need config
                if tag in sim_form.get(policy_to_sim, {}):
                    form_data = sim_form[policy_to_sim][tag]
                    for r in rd:
                        if r['YM'] not in data['data']:
                            data['data'][r['YM']] = []
                        for fd in form_data:
                            data['data'][r['YM']].append({'label': '%s%s' % (r['YM'], fd['label']) if fd['label'].startswith('_') else fd['label'],
                                                          'value': r[fd['value']],
                                                          'type': fd['type']})
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (tag, policy['title']))
            else:
                return jsonify(success=False, message='获取数据失败：%s' % msg)
            data['display_order'] = sorted(data['data'].keys())
            return jsonify(success=True, data=data, policy=policy_to_sim)
        elif policy_to_sim == '57a8cd3cc558f5000aac3f17':  # 2016年H2BCBH代表达成贡献奖
            # 读取试算方案所需的所有源数据。这实际上是确定计算单位的过程。
            sim_data, msg = _get_sim_data(policy_to_sim, uinfo, company_name, month)
            if sim_data:
                rd = sim_data
                data['cmn'].append({'label': '试算月份', 'value': month, 'type': 'static'})
                data['cmn'].append({'label': '员工姓名', 'value': rd[0]['USER_NAME'], 'type': 'static'})
                data['cmn'].append({'label': 'K账号', 'value': rd[0]['USER_CODE'], 'type': 'static'})
                data['cmn'].append({'label': 'TAG', 'value': rd[-1]['TAG_NAME'], 'type': 'static'})
                # need config
                # 注意：label中的空格和.要用_替换。
                if tag in sim_form.get(policy_to_sim, {}):
                    form_data = sim_form[policy_to_sim][tag]
                    for r in rd:  # 行
                        ym_title = _ym2title(r['YM'], postfix='数据')
                        if ym_title not in data['data']:
                            data['data'][ym_title] = []
                        for fd in form_data:  # 列
                            this_fd = { 'label': '%s%s' % (r['YM'], fd['label']) if fd['label'].startswith('_') else fd['label'],
                                        'value': r[fd['value']],
                                        'type': fd['type']}
                            if '结构外' in fd['label']:
                                this_fd['help'] = '代表TAG产品权重表以外的销量指标，作为结构外产品与最后一个结构内产品捆绑计算完成率。'
                            if '指标' in fd['label'] or '销量' in fd['label']:
                                this_fd['value'] = lib.round2float(this_fd['value'])
                            data['data'][ym_title].append(this_fd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (tag, policy['title']))
            else:
                return jsonify(success=False, message='获取数据失败：%s' % msg)
            data['display_order'] = []
            for ymk in range(201607, 201613):
                ymt = _ym2title(str(ymk), postfix='数据')
                if ymt.decode('utf-8') in data['data']:
                    data['display_order'].append(ymt)
            return jsonify(success=True, data=data, policy=policy_to_sim)
        elif policy_to_sim == '57a8d32dc558f500316898a2':  # 2016年H2BCBH代表增长奖
            # 读取试算方案所需的所有源数据。这实际上是确定计算单位的过程。
            sim_data, msg = _get_sim_data(policy_to_sim, uinfo, company_name, month)
            if sim_data:
                rd = sim_data
                data['cmn'].append({'label': '试算月份', 'value': month, 'type': 'static'})
                data['cmn'].append({'label': '员工姓名', 'value': rd[0]['USER_NAME'], 'type': 'static'})
                data['cmn'].append({'label': 'K账号', 'value': rd[0]['USER_CODE'], 'type': 'static'})
                data['cmn'].append({'label': 'TAG', 'value': rd[-1]['TAG_NAME'], 'type': 'static'})
                # need config
                # 注意：label中的空格和.要用_替换。
                if tag in sim_form.get(policy_to_sim, {}):
                    form_data = sim_form[policy_to_sim][tag]
                    for r in rd:
                        ym_title = _ym2title(r['YM'], postfix='数据')
                        if ym_title not in data['data']:
                            data['data'][ym_title] = []
                        for fd in form_data:
                            this_fd = {'label': '%s%s' % (r['YM'], fd['label']) if fd['label'].startswith('_') else fd['label'],
                                       'value': r[fd['value']],
                                       'type': fd['type']}
                            if '结构外' in fd['label']:
                                this_fd['help'] = '代表TAG产品权重表以外的销量指标，作为结构外产品与最后一个结构内产品捆绑计算完成率。'
                            if '指标' in fd['label'] or '销量' in fd['label']:
                                this_fd['value'] = lib.round2float(this_fd['value'])
                            data['data'][ym_title].append(this_fd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (tag, policy['title']))
            else:
                return jsonify(success=False, message='获取数据失败：%s' % msg)
            data['display_order'] = []
            for ymk in range(201607, 201613):
                ymt = _ym2title(str(ymk), postfix='数据')
                if ymt.decode('utf-8') in data['data']:
                    data['display_order'].append(ymt)
            return jsonify(success=True, data=data, policy=policy_to_sim)
        elif policy_to_sim == '573d588f447de7000bf259c2':  # 2016年County代表销售绩效奖
            # 读取试算方案所需的所有源数据。这实际上是确定计算单位的过程。
            sim_data, msg = _get_sim_data(policy_to_sim, uinfo, company_name, month)
            if sim_data:
                rd = sim_data
                data['cmn'].append({'label': '试算月份', 'value': month, 'type': 'static'})
                data['cmn'].append({'label': '员工姓名', 'value': rd[0]['USER_NAME'], 'type': 'static'})
                data['cmn'].append({'label': 'K账号', 'value': rd[0]['USER_CODE'], 'type': 'static'})
                data['cmn'].append({'label': 'TAG', 'value': rd[-1]['TAG_NAME'], 'type': 'static'})
                # need config
                # 注意：label中的空格和.要用_替换。
                if tag in sim_form.get(policy_to_sim, {}):
                    form_data = sim_form[policy_to_sim][tag]
                    for r in rd:
                        ym_title = _ym2title(r['YM'], postfix='数据')
                        if ym_title not in data['data']:
                            data['data'][ym_title] = []
                        for fd in form_data:
                            if fd['label'].startswith('_'):
                                data['data'][ym_title].append({'label': '%s%s' % (r['YM'], fd['label']),
                                                              'value': lib.round2float(r[fd['value']]) if '指标' in fd['label'] or '销量' in fd['label'] else r[fd['value']],
                                                              'type': fd['type']})
                    for fd in form_data:
                        if not fd['label'].startswith('_'):
                            data['cmn'].append({'label': fd['label'],
                                                'value': fd['value'],
                                                'type': fd['type']})
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (tag, policy['title']))
            else:
                return jsonify(success=False, message='获取数据失败：%s' % msg)
            data['display_order'] = []
            for ymk in range(201607, 201613):
                ymt = _ym2title(str(ymk), postfix='数据')
                if ymt.decode('utf-8') in data['data']:
                    data['display_order'].append(ymt)
            return jsonify(success=True, data=data, policy=policy_to_sim)
        elif policy_to_sim == '59ae589de9c6a300349edc53': # 2017年BCBH代表达成贡献奖-模算
            # 读取试算方案所需的所有源数据。这实际上是确定计算单位的过程。
            sim_data, msg = _get_sim_data(policy_to_sim, uinfo, company_name, month)
            if sim_data:
                rd = sim_data
                data['cmn'].append({'label': '试算月份', 'value': month, 'type': 'static'})
                data['cmn'].append({'label': '员工姓名', 'value': rd[0]['USER_NAME'], 'type': 'static'})
                data['cmn'].append({'label': 'K账号', 'value': rd[0]['USER_CODE'], 'type': 'static'})
                data['cmn'].append({'label': 'TAG', 'value': rd[-1]['TAG_NAME'], 'type': 'static'})
                # need config
                # 注意：label中的空格和.要用_替换。
                if tag in sim_form.get(policy_to_sim, {}):
                    form_data = sim_form[policy_to_sim][tag]
                    for r in rd:
                        ym_title = _ym2title(r['YM'], postfix='数据')
                        if ym_title not in data['data']:
                            data['data'][ym_title] = []
                        for fd in form_data:
                            this_fd = {'label': '%s%s' % (r['YM'], fd['label']) if fd['label'].startswith('_') else fd[
                                'label'],
                                       'value': r[fd['value']],
                                       'type': fd['type']}
                            if '结构外' in fd['label']:
                                this_fd['help'] = '代表TAG产品权重表以外的销量指标，作为结构外产品与最后一个结构内产品捆绑计算完成率。'
                            if '指标' in fd['label'] or '销量' in fd['label']:
                                this_fd['value'] = lib.round2float(this_fd['value'])
                            data['data'][ym_title].append(this_fd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (tag, policy['title']))
            else:
                return jsonify(success=False, message='获取数据失败：%s' % msg)
            data['display_order'] = []
            for ymk in range(201707, 201713):
                ymt = _ym2title(str(ymk), postfix='数据')
                if ymt.decode('utf-8') in data['data']:
                    data['display_order'].append(ymt)
            return jsonify(success=True, data=data, policy=policy_to_sim)
        elif policy_to_sim == '59ae58a5e9c6a300349edc84': # 2017年BCBH代表增长奖-模算
            # 读取试算方案所需的所有源数据。这实际上是确定计算单位的过程。
            sim_data, msg = _get_sim_data(policy_to_sim, uinfo, company_name, month)
            if sim_data:
                rd = sim_data
                data['cmn'].append({'label': '试算月份', 'value': month, 'type': 'static'})
                data['cmn'].append({'label': '员工姓名', 'value': rd[0]['USER_NAME'], 'type': 'static'})
                data['cmn'].append({'label': 'K账号', 'value': rd[0]['USER_CODE'], 'type': 'static'})
                data['cmn'].append({'label': 'TAG', 'value': rd[-1]['TAG_NAME'], 'type': 'static'})
                # need config
                # 注意：label中的空格和.要用_替换。
                if tag in sim_form.get(policy_to_sim, {}):
                    form_data = sim_form[policy_to_sim][tag]
                    for r in rd:
                        ym_title = _ym2title(r['YM'], postfix='数据')
                        if ym_title not in data['data']:
                            data['data'][ym_title] = []
                        for fd in form_data:
                            this_fd = {'label': '%s%s' % (r['YM'], fd['label']) if fd['label'].startswith('_') else fd[
                                'label'],
                                       'value': r[fd['value']],
                                       'type': fd['type']}
                            if '结构外' in fd['label']:
                                this_fd['help'] = '代表TAG产品权重表以外的销量指标，作为结构外产品与最后一个结构内产品捆绑计算完成率。'
                            if '指标' in fd['label'] or '销量' in fd['label']:
                                this_fd['value'] = lib.round2float(this_fd['value'])
                            data['data'][ym_title].append(this_fd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (tag, policy['title']))
            else:
                return jsonify(success=False, message='获取数据失败：%s' % msg)
            data['display_order'] = []
            for ymk in range(201707, 201713):
                ymt = _ym2title(str(ymk), postfix='数据')
                if ymt.decode('utf-8') in data['data']:
                    data['display_order'].append(ymt)
            return jsonify(success=True, data=data, policy=policy_to_sim)
        elif policy_to_sim == '58abf09628112c000ae0b8d2': # 2017年County代表销售绩效奖-模算

            # 读取试算方案所需的所有源数据。这实际上是确定计算单位的过程。
            sim_data, msg = _get_sim_data(policy_to_sim, uinfo, company_name, month)
            if sim_data:
                rd = sim_data
                data['cmn'].append({'label': '试算月份', 'value': month, 'type': 'static'})
                data['cmn'].append({'label': '员工姓名', 'value': rd[0]['USER_NAME'], 'type': 'static'})
                data['cmn'].append({'label': 'K账号', 'value': rd[0]['USER_CODE'], 'type': 'static'})
                data['cmn'].append({'label': 'TAG', 'value': rd[-1]['TAG_NAME'], 'type': 'static'})
                # need config
                # 注意：label中的空格和.要用_替换。
                if tag in sim_form.get(policy_to_sim, {}):
                    form_data = sim_form[policy_to_sim][tag]
                    for r in rd:
                        ym_title = _ym2title(r['YM'], postfix='数据')
                        if ym_title not in data['data']:
                            data['data'][ym_title] = []
                        for fd in form_data:
                            if fd['label'].startswith('_'):
                                data['data'][ym_title].append({'label': '%s%s' % (r['YM'], fd['label']),
                                                              'value': lib.round2float(r[fd['value']]) if '指标' in fd['label'] or '销量' in fd['label'] else r[fd['value']],
                                                              'type': fd['type']})
                    for fd in form_data:
                        if not fd['label'].startswith('_'):
                            data['cmn'].append({'label': fd['label'],
                                                'value': fd['value'],
                                                'type': fd['type']})
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (tag, policy['title']))
            else:
                return jsonify(success=False, message='获取数据失败：%s' % msg)
            data['display_order'] = []
            for ymk in range(201707, 201713):
                ymt = _ym2title(str(ymk), postfix='数据')
                if ymt.decode('utf-8') in data['data']:
                    data['display_order'].append(ymt)
            return jsonify(success=True, data=data, policy=policy_to_sim)

        elif policy_to_sim == '5aa744c2139976000ddf106e': # 2018年BCBH&County代表达成贡献奖-模拟
            uinfo = db.get_sim_hierarchy(user_id.upper(), company_name)
            # 读取试算方案所需的所有源数据。这实际上是确定计算单位的过程。
            sim_data, msg = _get_sim_data(policy_to_sim, uinfo, company_name, month)
            if sim_data:
                rd = sim_data
                data['cmn'].append({'label': '试算月份', 'value': month, 'type': 'static'})
                data['cmn'].append({'label': '员工姓名', 'value': rd[0]['USER_NAME'], 'type': 'static'})
                data['cmn'].append({'label': 'K账号', 'value': rd[0]['USER_CODE'], 'type': 'static'})
                data['cmn'].append({'label': 'TAG', 'value': rd[-1]['TAG_NAME'], 'type': 'static'})
                # need config
                # 注意：label中的空格和.要用_替换。
                if tag in sim_form.get(policy_to_sim, {}):
                    form_data = sim_form[policy_to_sim][tag]
                    for r in rd:
                        ym_title = _ym2title(r['YM'], postfix='数据')
                        if ym_title not in data['data']:
                            data['data'][ym_title] = []
                        for fd in form_data:
                            if fd['label'].startswith('_'):
                                data['data'][ym_title].append({'label': '%s%s' % (r['YM'], fd['label']),
                                                              'value': lib.round2float(r[fd['value']]) if '指标' in fd['label'] or '销量' in fd['label'] else r[fd['value']],
                                                              'type': fd['type']})
                    for fd in form_data:
                        if not fd['label'].startswith('_'):
                            data['cmn'].append({'label': fd['label'],
                                                'value': fd['value'],
                                                'type': fd['type']})
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (tag, policy['title']))
            else:
                return jsonify(success=False, message='获取数据失败：%s' % msg)
            data['display_order'] = []
            for ymk in range(201801, 201807):
                ymt = _ym2title(str(ymk), postfix='数据')
                if ymt.decode('utf-8') in data['data']:
                    data['display_order'].append(ymt)
            return jsonify(success=True, data=data, policy=policy_to_sim)
        elif policy_to_sim == '5aa74591139976002c3c7aee': # 2018年BCBH&County代表增长奖-模拟

            # 读取试算方案所需的所有源数据。这实际上是确定计算单位的过程。
            sim_data, msg = _get_sim_data(policy_to_sim, uinfo, company_name, month)
            if sim_data:
                rd = sim_data
                data['cmn'].append({'label': '试算月份', 'value': month, 'type': 'static'})
                data['cmn'].append({'label': '员工姓名', 'value': rd[0]['USER_NAME'], 'type': 'static'})
                data['cmn'].append({'label': 'K账号', 'value': rd[0]['USER_CODE'], 'type': 'static'})
                data['cmn'].append({'label': 'TAG', 'value': rd[-1]['TAG_NAME'], 'type': 'static'})
                # need config
                # 注意：label中的空格和.要用_替换。
                if tag in sim_form.get(policy_to_sim, {}):
                    form_data = sim_form[policy_to_sim][tag]
                    for r in rd:
                        ym_title = _ym2title(r['YM'], postfix='数据')
                        if ym_title not in data['data']:
                            data['data'][ym_title] = []
                        for fd in form_data:
                            if fd['label'].startswith('_'):
                                data['data'][ym_title].append({'label': '%s%s' % (r['YM'], fd['label']),
                                                              'value': lib.round2float(r[fd['value']]) if '指标' in fd['label'] or '销量' in fd['label'] else r[fd['value']],
                                                              'type': fd['type']})
                    for fd in form_data:
                        if not fd['label'].startswith('_'):
                            data['cmn'].append({'label': fd['label'],
                                                'value': fd['value'],
                                                'type': fd['type']})
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (tag, policy['title']))
            else:
                return jsonify(success=False, message='获取数据失败：%s' % msg)
            data['display_order'] = []
            for ymk in range(201801, 201807):
                ymt = _ym2title(str(ymk), postfix='数据')
                if ymt.decode('utf-8') in data['data']:
                    data['display_order'].append(ymt)
            return jsonify(success=True, data=data, policy=policy_to_sim)
        else:
            return jsonify(success=False, message='该奖金政策尚未支持模拟计算：%s' % policy['title'])
    elif company_name == 'saike': #saike
        env = const.ENV_SANDBOX
        color1 = '#F9BB28' # 黄色
        color2 = '#92D050' # 浅绿色
        color3 = '#00B0F0' # 蓝色
        # TODO 优化：多次查库SQL合并，数据库链接抽象为一个方法
        # 获取销售代表数据
        sql = "select * from \"%s\" where \"员工工号\"='%s' limit 1" % \
              (_get_data_file_file_id('员工数据', company_name, env=env), user_id)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
        r = requests.post(api_url, data={'sql': sql})
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message='身份验证失败[1]：%s' % r.json().get('message', '未知错误。'))
        employee_data = r.json().get('data', [])
        # 获取经理数据
        sql = "select * from \"%s\" where \"员工工号\"='%s' limit 1" % \
              (_get_data_file_file_id('经理主管数据', company_name, env=env), user_id)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
        r = requests.post(api_url, data={'sql': sql})
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message='身份验证失败[2]：%s' % r.json().get('message', '未知错误。'))
        manager_data = r.json().get('data', [])
        if not len(employee_data) == 1 and not len(manager_data) == 1:
            return jsonify(success=False, message='人员信息不全，请联系系统管理员。')
            # 员工类别为经理时
        if len(manager_data) == 1:
            level = 'manager'
            sql = "select * from \"%s\" where \"员工工号\"='%s' limit 1" % \
                  (_get_data_file_file_id('经理主管数据', company_name, env=env), user_id)
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败[6]：%s' % r.json().get('message', '未知错误。'))
            manager_data = r.json().get("data", [])
            if not len(manager_data) == 1:
                return jsonify(success=False, message='人员信息不全，请联系系统管理员。')
            base_label = [u'大区', u'办事处', u'员工工号', u'中文姓名', u'员工姓名', u'绩效期间']
            data = [{'title': b_label, 'label': b_label, 'value': manager_data[0].get(b_label), 'type': 'static',
                     'color': color1} for b_label in base_label if manager_data[0].get(b_label)]
            data.append({'title': '考核分数', 'label': '考核分数', 'value': 0, 'type': 'number', 'color': color3})
            # 获取经理所在地区的全部品规。
            sql = "select * from \"%s\" where \"办事处/地区\"='%s'" % \
                  (_get_data_file_file_id('绩效政策数据', company_name, env=env), manager_data[0].get(u'办事处/地区'))
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败[7]：%s' % r.json().get('message', '未知错误。'))
            type_data = r.json().get("data", [])
            medicine_type = list(set([t.get(u'品规', '') for t in type_data]))
            if len(type_data) == 0:
                return jsonify(success=False, message='品规信息不全，请联系系统管理员。')
            type_list = []
            for m_type in medicine_type:
                # 加入每一个品规
                if m_type:
                    data.append({'title': '品规', 'label': '品规', 'value': m_type, 'type': 'static', 'color': color2})
                    data.append(
                        {'title': '销量', 'label': '%s销量' % m_type, 'value': 0, 'type': 'number', 'color': color2})
        # 员工类别不为经理时
        else:
            # 获取员工基础信息
            level = 'employee'
            sql = "select * from \"%s\" where \"员工工号\"='%s' limit 1" % \
              (_get_data_file_file_id('员工数据', company_name, env=env), user_id)
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败[3]：%s' % r.json().get('message', '未知错误。'))
            report_relations_data = r.json().get("data", [])
            if not report_relations_data[0].get(u'办事处', []) or not len(report_relations_data) == 1:
                return jsonify(success=False, message='人员信息不全，请联系系统管理员。')
            data = [
                {'title': '大区', 'label': '大区', 'value': report_relations_data[0].get(u'大区'), 'type': 'static', 'color': color1},
                {'title': '办事处', 'label': '办事处', 'value': report_relations_data[0].get(u'办事处'), 'type': 'static', 'color': color1},
                # {'title': '地区', 'label': '地区', 'value': report_relations_data[0].get(u'地区'), 'type': 'static', 'color': color1},
                # {'title': '部门', 'label': '部门', 'value': report_relations_data[0].get(u'部门'), 'type': 'static', 'color': color1},
                {'title': '员工工号', 'label': '员工工号', 'value': report_relations_data[0].get(u'员工工号'), 'type': 'static', 'color': color1},
                {'title': '员工姓名', 'label': '员工姓名', 'value': report_relations_data[0].get(u'员工姓名'), 'type': 'static', 'color': color1},
                {'title': '绩效期间', 'label': '绩效期间', 'value': report_relations_data[0].get(u'绩效期间'), 'type': 'static', 'color': color1},
                # {'title': '人员分类', 'label': '考核分类', 'value': report_relations_data[0].get(u'考核分类'), 'type': 'static', 'color': color1}
            ]
            # 获取员工考核类型
            sql = "select * from \"%s\" where \"办事处\"='%s' limit 1" % \
                  (_get_data_file_file_id('办事处考核类型', company_name, quarter='2016', env=env), report_relations_data[0].get(u'办事处'))
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败[4]：%s' % r.json().get('message', '未知错误。'))
            growth_data = r.json().get("data", [])
            if not len(growth_data) == 1:
                return jsonify(success=False, message='人员信息不全，请联系系统管理员。')
            # data.append({'title': '考核类型', 'label': '考核类型', 'value': u'完成率', 'type': 'static', 'color': color1})
            # 输入项
            if u'完成率':
                data.append({'title': '本季度任务', 'label': '本季度任务', 'value': 0, 'type': 'number', 'color': color1})
            # 增长率考核方式暂时废弃，防止引起bug
            # elif growth_data[0].get(u"考核类型") == u'增长率':
            #     # 以下从结果中直接获取的，需要以后修正
            #     tmp_policy_id = u'579526543c279500099e3850'
            #     calc = db._find_all_in_org('Calculation', {'policy':tmp_policy_id}, 'saike').sort('created_at', pymongo.DESCENDING)[0]
            #     calc_id, owner = str(calc['_id']), calc['owner']
            #     result_id = str(db._find_all_in_org('Result', {'calculation': calc_id}, 'saike').sort('modified_at', pymongo.DESCENDING)[0]['_id'])
            #     query = {u'临床人员工号': user_id}
            #     r = db.get_result_by_id_with_query(result_id, owner, query)
            #     tmp_value = sum([d[u'前4季度平均销量'] for d in r[u'result']])  # r[u'result'][0][u'前4季度平均销量']
            #     data.append({'title': '前4季度平均销量', 'label': '前4季度平均销量', 'value': tmp_value, 'type': 'static', 'color': color3})
            # 获取销售代表所在地区的全部品规。
            sql = "select * from \"%s\" where \"办事处/地区\"='%s'" % \
                  (_get_data_file_file_id('绩效政策数据', company_name, env=env), employee_data[0].get(u'办事处/地区'))
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败[5]：%s' % r.json().get('message', '未知错误。'))
            type_data = r.json().get("data", [])
            medicine_type = list(set([t.get(u'品规', '') for t in type_data]))
            if len(type_data) == 0:
                return jsonify(success=False, message='品规信息不全，请联系系统管理员。')
            for m_type in medicine_type:
                # 加入每一个品规
                if m_type:
                    data.append({'title': '品规', 'label': '品规', 'value': m_type, 'type': 'static', 'color': color2})
                    data.append({'title': '本季度销量', 'label': '%s本季度流向' % m_type, 'value': 0, 'type': 'number', 'color': color2})

        return jsonify(success=True, data=data, level=level)
    elif company_name == 'hisunpfizer':
        use_tbl, CALC_QUARTER = _get_sim_source_table('', company_name)
        sql = "select * from \"%s\" where \"ntid\"='%s' limit 1" % \
              (use_tbl, user_id)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': sql})
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message='身份验证失败[8]：%s' % r.json().get('message', '未知错误。'))
        my_data = r.json().get('data', [])
        if not len(my_data) == 1:
            print 'can not find ntid:%s %s' % (company_name, user_id)
            return jsonify(success=False, message='对不起！该奖金模拟计算器仅支持医学信息专员使用！如有其它问题请发邮件至：COESystemOperation@hisun-pfizer.com')
        if not my_data[0].get('positionName', '').upper() == 'MICS':
            return jsonify(success=False, message='对不起！此功能仅提供给代表使用。')
        my_bu = my_data[0].get('bucode', 'n/a')
        data = [{'label': '员工姓名', 'value': my_data[0].get('name', 'n/a'), 'type': 'static'},
                {'label': '员工ID', 'value': my_data[0].get('code', 'n/a'), 'type': 'static'},
                {'label': '季度', 'value': CALC_QUARTER, 'type': 'static'},
                {'label': 'BU', 'value': 'ONC' if my_bu == 'ON' else my_bu, 'type': 'static'}]
        sql = "select * from \"%s\" where \"ntid\"='%s' and \"quarter\"='%s' and \"bucode\" = '%s'" % \
                  (use_tbl, user_id, CALC_QUARTER, my_bu)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': sql})
        if r.status_code == 200 and r.json().get('success', False):
            d_data = r.json().get('data', [])
            product_data = {}
            for_sort = {}
            for dd in d_data:
                # 产品名称
                product_name = dd['strengthname'] if not dd['strengthname'] else dd['strengthname'].strip()
                # package名称
                package_name = dd['packageName'] if not dd['packageName'] else dd['packageName'].strip()
                if not product_name or not package_name:
                    continue
                pkgcnt, cmt = lib.cast2float(dd['packageCount'])
                if cmt:
                    return jsonify(success=False, message=cmt)
                # 产品指标
                ptarget, cmt = lib.cast2float(dd['producttarget'])
                if cmt:
                    return jsonify(success=False, message=cmt)
                # package价格
                pkgprice, cmt = lib.cast2float(dd['packagePrice'])
                if cmt:
                    return jsonify(success=False, message=cmt)
                # package销售盒数
                pkgqty, cmt = lib.cast2float(dd['packageQuantity'])
                if cmt:
                    return jsonify(success=False, message=cmt)

                if product_name not in product_data:
                    product_data[product_name] = {'target': ptarget, 'packages': {}}
                    if ptarget not in for_sort:
                        for_sort[ptarget] = [product_name]
                    else:
                        if product_name not in for_sort[ptarget]:
                            for_sort[ptarget].append(product_name)
                if package_name not in product_data[product_name]['packages']:
                    product_data[product_name]['packages'][package_name] = {'sales_qty': pkgqty, 'price': pkgprice}
            for ptgt in sorted(for_sort.keys(), reverse=True):
                for prdt in for_sort[ptgt]:
                    this_prdt = {'label': '%s指标' % prdt, 'value': product_data[prdt]['target'], 'type': 'static', 'packages': []}
                    for pkg in sorted(product_data[prdt]['packages'].keys()):
                        this_prdt['packages'].append({'label': pkg, 'value': product_data[prdt]['packages'][pkg]['sales_qty'], 'type': 'number'})
                    data.append(this_prdt)
            return jsonify(success=True, data=data)
        else:
            return jsonify(success=False, message='获取数据失败：%s' % r.json().get('message', '未知错误。'))
    elif company_name == 'bayer':
        sql = "select * from \"%s\" where \"MRCode\"='%s'" % \
              (_get_sim_source_table('', company_name), user_id)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': sql})
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message='身份验证失败[8]：%s' % r.json().get('message', '未知错误。'))
        md = r.json().get('data', [])
        months = {}
        for d in md:
            mn = '%s月' % d['Month']
            mk = '%s月业绩' % d['Month']
            months[mk] = [  {'label': '%s全产品销量' % mn, 'value': d['AllSalesAmount'], 'type': 'number'},
                            {'label': '%s全产品指标' % mn, 'value': d['AllTargetAmount'], 'type': 'static'},
                            {'label': '%sNimotop Tab指标' % mn, 'value': d['N Tab_TargetAmount'], 'type': 'static'},
                            {'label': '%sBayaspirin销量' % mn, 'value': d['B_SalesAmount'], 'type': 'number'},
                            {'label': '%sBayaspirin指标' % mn, 'value': d['B_TargetAmount'], 'type': 'static'},
                            {'label': '%sAdalat30mg销量' % mn, 'value': d['A 30mg*7_SalesAmount'], 'type': 'number'},
                            {'label': '%sAdalat30mg指标' % mn, 'value': d['A 30mg*7_TargetAmount'], 'type': 'static'},
                            {'label': '%sAdalat60mg销量' % mn, 'value': d['A 60mg_SalesAmount'], 'type': 'number'},
                            {'label': '%sAdalat60mg指标' % mn, 'value': d['A 60mg_TargetAmount'], 'type': 'static'},
                            ]
        return jsonify(success=True, data={ 'cmn': [{'label': '员工姓名', 'value': 'MMM', 'type': 'static'},
                                                    {'label': 'IPIN', 'value': user_id, 'type': 'static'},
                                                    {'label': '职位', 'value': 'MR', 'type': 'static'},
                                                    {'label': '产品线', 'value': md[0]['TerritoryTypeName'], 'type': 'static'},
                                                    {'label': 'TerritoryCode', 'value': md[0]['TerritoryCode'], 'type': 'static'},
                                                    {'label': 'TerritoryName', 'value': md[0]['TerritoryName'], 'type': 'static'},
                                                    {'label': '代岗', 'value': md[0]['MRIsSubstitute'], 'type': 'static'},
                                                    ],
                                            'display_order': sorted(months.keys()),
                                            'data': months
                                        })
    elif company_name == 'kaniontest':
        user_info = {
            'name': '唐莉莉',
            'user_code': 'TLL1801',
            'level': 'REP',
            'bu': '主品种'
        }
        user_id = user_info['user_code']
        policy = db.get_policy_in_org(policy_id, company_name)
        if not policy:
            return jsonify(success=False, message=txt.POLICY_NOT_FOUND, data={})
        sim_policy_calc = {
            "5b711d717409a3000c7e1ba6": "5b716e413ae876000a2167fb",
        }
        sim_policy_kpi = {
            '5b711d717409a3000c7e1ba6': [
                u"销售片区", u"省公司", u"办事处", u"购入客户", u"品种简称", u"终端品种", u"购入责任人工号", u"购入责任人姓名",
                u"医院分类", u"产品类型", u"产品线", u"主体", u"考核分类", u"Q2数量", u"Q2消化金额", u"考核金额(扣减返利)",
                u"费用考核金额(中标0_dot_93)", u"兑现计提费用额", u"2017年均值标准", u"考核均值分类", u"2018年计划金额",
                u"2017年同期金额", u"兑现标准", u"终端完成率", u"代表整体计划金额", u"代表整体达成金额", u"代表整体完成率",
                u"考核兑现标准", u"考核兑现金额", u"增幅兑现", u"发放兑现金额", u"分类", u"月均(含新开发)", u"是否新代表",
                u"是否环比增长", u"二季度兑现拉通发放", u"4月省公司", u"5月省公司", u"4月发放兑现", u"5月发放兑现", u"6月发放兑现"],
        }
        if sim_policy_calc.get(policy_id):
            sim_calc_id = sim_policy_calc[policy_id]
        else:
            return jsonify(success=False, message="找不到对应的计算", data={})
        calc = db.get_calc_in_org(sim_calc_id, company_name)
        data_version = calc['hierarchy_source']['id']
        data_map = calc['kpi_map']['data'][data_version]
        r = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_VERSION_INFO, data_version), company_name, const.ENV_PRODUCTION))
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="无效的数据来源[0]", data={})
        file_file_id = r.json().get('data', {}).get('file_file_id', '')
        if not file_file_id:
            return jsonify(success=False, message="无效的数据来源[1]", data={})

        _sql_filter = " and ".join(["\"%s\"='%s'" % (data_map[u"购入责任人工号"], user_id)])
        _sql = "select * from \"{data_version}\" where {sql_filter}".format(data_version=file_file_id, sql_filter=_sql_filter)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': _sql})
        if not(r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="获取数据失败！1", data={})
        source_data = r.json().get('data', [])
        if not source_data:
            return jsonify(success=False, message="未找到对应人员销售指标！", data={})
        if data_map:
            data = []
            for kpi in sim_policy_kpi[policy_id]:
                if data_map.get(kpi) and source_data[0].get(data_map.get(kpi)) is not None:
                    row = {}
                    if u'数量' in kpi or u'金额' in kpi or u'标准' in kpi or u'兑现' in kpi:
                        value = source_data[0][data_map.get(kpi)]
                        v_type = 'number'
                        row = {'title': kpi,
                               'label': data_map.get(kpi),
                               'value': value,
                               'type': v_type}
                    else:
                        value = source_data[0][data_map.get(kpi)]
                        v_type = 'static'
                        row = {'title': kpi,
                               'label': data_map.get(kpi),
                               'value': value,
                               'type': v_type}
                    if row:
                        data.append(row)
            return jsonify(success=True, message="", data=data)
        else:
            return jsonify(success=False, message="获取数据失败！3", data={})
    elif company_name == 'gvtest':
        user_info = db.get_sim_hierarchy(user_id, company_name)
        user_id, user_position = user_info['user_code'], user_info['terr_id']
        policy = db.get_policy_in_org(policy_id, company_name)
        if not policy:
            return jsonify(success=False, message=txt.POLICY_NOT_FOUND, data={})
        sim_policy_calc = {
            "5b70ec1a3119a00081b41cec": "5b70f5343119a00081b41cf1",
        }
        sim_policy_kpi = {
            '5b70ec1a3119a00081b41cec': [u'员工号', u'员工姓名', u'岗位编码', u'季度纯销销量', u'季度纯销指标'],
        }
        if sim_policy_calc.get(policy_id):
            sim_calc_id = sim_policy_calc[policy_id]
        else:
            return jsonify(success=False, message="找不到对应的计算", data={})
        calc = db.get_calc_in_org(sim_calc_id, company_name)
        data_version = calc['hierarchy_source']['id']
        data_map = calc['kpi_map']['data'][data_version]
        r = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_VERSION_INFO, data_version), company_name, const.ENV_PRODUCTION))
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="无效的数据来源[0]", data={})
        file_file_id = r.json().get('data', {}).get('file_file_id', '')
        if not file_file_id:
            return jsonify(success=False, message="无效的数据来源[1]", data={})
        _sql_filter = " and ".join(["\"%s\"='%s'" % (data_map[u"员工号"], user_id), "\"%s\"='%s'" % (data_map[u"岗位编码"], user_position)])
        _sql = "select * from \"{data_version}\" where {sql_filter}".format(data_version=file_file_id, sql_filter=_sql_filter)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': _sql})
        if not(r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="获取数据失败！1", data={})
        source_data = r.json().get('data', [])
        if not source_data:
            return jsonify(success=False, message="未找到对应人员销售指标！", data={})
        if data_map:
            data = []
            for kpi in sim_policy_kpi[policy_id]:
                if data_map.get(kpi) and source_data[0].get(data_map.get(kpi)) is not None:
                    row = {}
                    if u'销量' not in kpi and u'发货' not in kpi and u'精细/总代' not in kpi and u'民营' not in kpi or u'当季度纯销指标(含民营)' in kpi:
                        value = source_data[0][data_map.get(kpi)]
                        v_type = 'static'
                        row = {'title': kpi,
                               'label': data_map.get(kpi),
                               'value': value,
                               'type': v_type}
                    elif u'销量' in kpi or u'发货销量' in kpi or u'发货量' in kpi or u'发货指标' in kpi or u'YTD去年发货指标' in kpi or u'民营纯销指标' in kpi :
                        value = float(source_data[0][data_map.get(kpi)])
                        v_type = 'number'
                        row = {'title': kpi,
                               'label': data_map.get(kpi),
                               'value': value,
                               'type': v_type}
                    elif u'精细/总代' in kpi:
                        value = source_data[0][data_map.get(kpi)]
                        v_type = 'select'
                        row = {'title': kpi,
                               'label': data_map.get(kpi),
                               'value': value,
                               'type': v_type,
                               'option': ["精细", "总代"]}
                    if row:
                        data.append(row)
            return jsonify(success=True, message="", data=data)
        else:
            return jsonify(success=False, message="获取数据失败！3", data={})
    elif company_name == 'greenvalley':
        user_info = db.get_sim_hierarchy(user_id, company_name)
        user_id, user_position = user_info['user_code'], user_info['terr_id']
        # user_id, user_position = 'LGYY000000', 'MR_LGYY000000'
        policy = db.get_policy_in_org(policy_id, company_name)
        if not policy:
            return jsonify(success=False, message=txt.POLICY_NOT_FOUND, data={})
        # kpis = db.get_kpi_by_policy(policy_id, policy['owner'])
        sim_policy_calc = {
            '5aa8d518033bf50022b3b9dc': '5ad5b6bd7bdddb000a30980a',
            '5aa8e20c033bf5002c38b797': '5ad5ccea7bdddb000cf028c7',
            '5ab232f9ef90fc00317e2e85': '5ad5cfb67bdddb000bcd5e40',
            '5ab23ca8ef90fc00317e2e97': '5af1be939ccc52002c8223fe',
            '5ab24b4fef90fc00367909c3': '5ad6e0897bdddb005431c442',
            '5ad6e8287bdddb005efd905d': '5ae3c9924fac450009234a02',
            '5ae1efaed32066000c6ba115': '5ae80e0e7fe3fa000c48e6c0',
            '5ae1f39fd32066000d1f9e22': '5ae1f724d32066000d1f9e2d',
            '5ae3f8b8b577b4000aa921f6': '5ae3f92fb577b4000aa9221c',
            '5aeaaefaa5b5cc000990383c': '5aeab151a5b5cc003b36f832',
            '5aeaaffca5b5cc003622c57f': '5aeab3e7a5b5cc0009903854',
            '5b1dd908fa5f660022942024': '5b1ddb69fa5f660022942037',
            '5ab22b66ef90fc00277da84b': '5b28787eb29756000a10b258',
            '5ab24056ef90fc00317e2e9e': '5b287ba8b297560009a67365'
        }
        sim_policy_kpi = {
            '5aa8d518033bf50022b3b9dc': [u'员工号', u'员工姓名', u'岗位编码', u'季度销量', u'季度指标'],
            '5aa8e20c033bf5002c38b797': [u'员工号', u'员工姓名', u'岗位编码', u'季度销量', u'季度指标'],
            '5ab232f9ef90fc00317e2e85': [u'员工号', u'员工姓名', u'岗位编码', u'精细/总代', u'当季度纯销销量',
                                         u'当季度纯销指标', u'去年纯销销量',u'YTD发货销量', u'YTD发货指标'],
            '5ab23ca8ef90fc00317e2e97': [u'员工号', u'员工姓名', u'岗位编码', u'当季度纯销销量', u'当季度纯销指标'],
            '5ab24b4fef90fc00367909c3': [u'员工号', u'员工姓名', u'岗位编码', u'当季度纯销销量', u'当季度纯销指标',
                                         u'YTD发货销量', u'YTD发货指标'],
            '5ad6e8287bdddb005efd905d': [u'员工号', u'员工姓名', u'岗位编码', u'精细/总代', u'当季度民营纯销销量',
                                         u'当季度民营纯销指标', u'当季度纯销销量(不含民营)', u'当季度纯销指标(不含民营)',
                                         u'去年纯销销量(不含民营)', u'YTD发货销量', u'YTD发货指标'],
            '5ae1efaed32066000c6ba115': [u'员工号', u'员工姓名', u'岗位编码', u'季度发货量', u'季度发货指标'],
            '5ae1f39fd32066000d1f9e22': [u'员工号', u'员工姓名', u'岗位编码', u'季度纯销销量', u'季度纯销指标'],
            '5ae3f8b8b577b4000aa921f6': [u'员工号', u'员工姓名', u'岗位编码', u'精细/总代', u'当季度纯销销量',
                                         u'当季度纯销指标', u'去年纯销销量', u'YTD发货销量', u'YTD发货指标'],
            '5aeaaefaa5b5cc000990383c': [u'员工号', u'员工姓名', u'岗位编码', u'季度销量', u'季度指标'],
            '5aeaaffca5b5cc003622c57f': [u'员工号', u'员工姓名', u'岗位编码', u'季度纯销销量', u'季度纯销指标'],
            '5b1dd908fa5f660022942024': [u'员工号', u'员工姓名', u'季度纯销销量', u'季度纯销指标'],
            '5ab22b66ef90fc00277da84b': [u'员工号', u'员工姓名', u'岗位编码', u'季度总销量', u'季度总指标'],
            '5ab24056ef90fc00317e2e9e': [u'员工号', u'员工姓名', u'岗位编码', u'YTD发货销量', u'YTD发货指标',
                                         u'当季度纯销销量(含民营)', u'当季度纯销指标(含民营)',
                                         u'当季度民营纯销销量', u'当季度民营纯销指标']
        }
        if sim_policy_calc.get(policy_id):
            sim_calc_id = sim_policy_calc[policy_id]
        else:
            return jsonify(success=False, message="找不到对应的计算", data={})
        calc = db.get_calc_in_org(sim_calc_id, company_name)
        data_version = calc['hierarchy_source']['id']
        data_map = calc['kpi_map']['data'][data_version]
        r = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_VERSION_INFO, data_version), company_name, const.ENV_PRODUCTION))
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="无效的数据来源[0]", data={})
        file_file_id = r.json().get('data', {}).get('file_file_id', '')
        if not file_file_id:
            return jsonify(success=False, message="无效的数据来源[1]", data={})
        _sql_filter = " and ".join(["\"%s\"='%s'" % (data_map[u"员工号"], user_id), "\"%s\"='%s'" % (data_map[u"岗位编码"], user_position)])
        _sql = "select * from \"{data_version}\" where {sql_filter}".format(data_version=file_file_id, sql_filter=_sql_filter)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': _sql})
        if not(r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="获取数据失败！1", data={})
        source_data = r.json().get('data', [])
        if not source_data:
            return jsonify(success=False, message="未找到对应人员销售指标！", data={})
        if data_map:
            data = []
            for kpi in sim_policy_kpi[policy_id]:
                if data_map.get(kpi) and source_data[0].get(data_map.get(kpi)) is not None:
                    row = {}
                    if u'销量' not in kpi and u'发货' not in kpi and u'精细/总代' not in kpi and u'民营' not in kpi or u'当季度纯销指标(含民营)' in kpi:
                        value = source_data[0][data_map.get(kpi)]
                        v_type = 'static'
                        row = {'title': kpi,
                               'label': data_map.get(kpi),
                               'value': value,
                               'type': v_type}
                    elif u'销量' in kpi or u'发货销量' in kpi or u'发货量' in kpi or u'发货指标' in kpi or u'YTD去年发货指标' in kpi or u'民营纯销指标' in kpi :
                        value = float(source_data[0][data_map.get(kpi)])
                        v_type = 'number'
                        row = {'title': kpi,
                               'label': data_map.get(kpi),
                               'value': value,
                               'type': v_type}
                    elif u'精细/总代' in kpi:
                        value = source_data[0][data_map.get(kpi)]
                        v_type = 'select'
                        row = {'title': kpi,
                               'label': data_map.get(kpi),
                               'value': value,
                               'type': v_type,
                               'option': ["精细", "总代"]}
                    if row:
                        data.append(row)
            # 复杂方案的定制
            # 2018-自营-大区经理
            if policy_id == '5ab22b66ef90fc00277da84b':
                subs_file_id = _get_data_file_file_id('模拟数据', company_name, table_name='自营-区域经理-for大区模拟器')
                _sql = "select * from \"%s\" where \"大区经理\"='%s' and \"大区经理岗位号\"='%s'" % (
                    subs_file_id, source_data[0][u'员工号'], source_data[0][u'岗位编码']
                )
                api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
                r = requests.post(api_url, data={'sql': _sql})
                if not (r.status_code == 200 and r.json().get('success', False)):
                    return jsonify(success=False, message='获取下属数据失败：%s' % r.json().get('message', '未知错误。'))
                sub_source_data = r.json().get('data', [])
                count = 1
                for sub in sub_source_data:
                    data.append({'title': '下属姓名',
                                   'label': "sub_name_%s" % count,
                                   'value': sub[u'员工姓名'],
                                   'type': 'static'})
                    data.append({'title': '下属岗位编码',
                                   'label': "sub_area_%s" % count,
                                   'value': sub[u'岗位编码'],
                                   'type': 'static'})
                    data.append({'title': '下属达成率',
                                   'label': "sub_rate_%s" % count,
                                   'value': sub[u'季度达成率'],
                                   'type': 'number'})
                    count += 1
            #  2018-民营&招商-大区(副)经理
            if policy_id == '5ab24056ef90fc00317e2e9e':
                subs_file_id = _get_data_file_file_id('模拟数据', company_name, table_name='招商经理/主管-for大区经理模拟器')
                _sql = "select * from \"%s\" where \"大区经理\"='%s' and \"大区经理岗位号\"='%s'" % (
                    subs_file_id, source_data[0][u'员工号'], source_data[0][u'岗位编码']
                )
                api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
                r = requests.post(api_url, data={'sql': _sql})
                if not (r.status_code == 200 and r.json().get('success', False)):
                    return jsonify(success=False, message='获取下属数据失败：%s' % r.json().get('message', '未知错误。'))
                sub_source_data = r.json().get('data', [])
                count = 1
                for sub in sub_source_data:
                    data.append({'title': '下属姓名',
                                   'label': "sub_name_%s" % count,
                                   'value': sub[u'员工姓名'],
                                   'type': 'static'})
                    data.append({'title': '下属岗位编码',
                                   'label': "sub_area_%s" % count,
                                   'value': sub[u'岗位编码'],
                                   'type': 'static'})
                    data.append({'title': '下属达成率',
                                   'label': "sub_rate_%s" % count,
                                   'value': sub[u'当季度纯销达成率'],
                                   'type': 'number'})
                    data.append({'title': '下属同期增长率',
                                   'label': "sub_growth_%s" % count,
                                   'value': sub[u'同期增长率'],
                                   'type': 'number'})
                    data.append({'title': '下属YTD发货达成率',
                                   'label': "sub_send_%s" % count,
                                   'value': sub[u'YTD发货达成率'],
                                   'type': 'number'})
                    count += 1
            return jsonify(success=True, message="", data=data)
        else:
            return jsonify(success=False, message="获取数据失败！3", data={})
    else:
        return jsonify(success=False, message='Invalid company name: %s' % company_name)


@app.route('/api/level')
def api_level():
    # 验证通过SSO登录的用户的JWT
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    if company_name == 'saike':
        env = const.ENV_SANDBOX
        sql = "select * from \"%s\" where \"员工工号\"='%s' limit 1" % \
              (_get_data_file_file_id('员工数据', company_name, env=env), user_id)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
        r = requests.post(api_url, data={'sql': sql})
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message='身份验证失败[1]：%s' % r.json().get('message', '未知错误。'))
        employee_data = r.json().get('data', [])
        # 获取经理数据
        sql = "select * from \"%s\" where \"员工工号\"='%s' limit 1" % \
              (_get_data_file_file_id('经理主管数据', company_name, env=env), user_id)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
        r = requests.post(api_url, data={'sql': sql})
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message='身份验证失败[2]：%s' % r.json().get('message', '未知错误。'))
        manager_data = r.json().get('data', [])
        if not len(employee_data) == 1 and not len(manager_data) == 1:
            return jsonify(success=False, message='人员信息不全，请联系系统管理员。')
        # 员工类别不为经理时
        if not len(manager_data) == 1:
            return jsonify(success=True, data={'level': 'employee'})
        else:
            return jsonify(success=True, data={'level': 'manager'})
    elif company_name == 'az':
        uinfo = db.get_sim_hierarchy(user_id.upper(), company_name)
        if uinfo:
            tag = uinfo['tag']
            level = uinfo['level']
            file_tag = ''
            if level == 'REP':
                rep_tags = ['BCA', 'BCAF', 'BCF', 'BCZ', 'BCAZ', 'CHC', 'CT', 'CVB', 'CVC', 'CVK', 'CVX_C', 'CVX_E', 'DMO',
                            'DMF', 'GIALL_C', 'GIALL_E', 'GIIV', 'GIOral', 'LCI_1', 'LCI_2', 'LCI', 'LCIT', 'LCT',
                            'OCMIX_C', 'OCMIX_E', 'PBG_C', 'PBG_E', 'RE1', 'RE2', 'RE3', 'RE2_MIX', 'RE2_PB', 'RE_CHC']
                if tag in rep_tags:
                    re_sp_tag = {'CHC': 'RE_CHC', 'CT': 'County', 'LCI_1': 'LCI', 'LCI_2': 'LCI'}
                    file_tag = "tag_%s" % (tag if tag not in re_sp_tag.keys() else re_sp_tag[tag])
            elif level == 'DSM':
                dsm_tags = ['CA', 'BCAF', 'BCF', 'BCZ', 'CHC', 'CT', 'CVB', 'CVC', 'CVK', 'CVX', 'DMO', 'DMF','GIALL_C',
                            'GIALL_E', 'GIIV', 'GIOral', 'LCI', 'OCMIX', 'PBG', 'RE1', 'RE2', 'RE3']
                if tag in dsm_tags:
                    dsm_sp_tags = {'CHC': 'RE_CHC', 'CT': 'County', 'CVX': 'CVX_C', 'OCMIX': 'OCMIX_C', 'PBG': 'PGB_C'}
                    file_tag = "tag_%s_dsm" % (tag if tag not in dsm_sp_tags.keys() else dsm_sp_tags[tag])
            data = {'tag': tag, 'level': level, 'file_tag': file_tag.lower()}
            return jsonify(success=True, data=data)
        else:
            return jsonify(success=False, message='没有对应的人员信息！')
    else:
        return jsonify(success=False, message='Invalid company name: %s' % company_name)


@app.route('/api/sim/exec', methods=['POST'])
def api_exec_sim():
    # 验证通过SSO登录的用户的JWT
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    if company_name == 'az':
        sim_user = request.form.get(u'K账号', '')
        sim_tag = request.form.get('TAG', '')
        if not (sim_user.upper() == user_id.upper() and sim_tag):
            return jsonify(success=False, message='无法确定计算单位：[%s][%s]' % (sim_user, sim_tag))
        policy_id = request.form.get('policy', '')
        sim_policy = db._find_one_in_org('Policy', {'_id': ObjectId(policy_id)}, company_name)
        if not sim_policy:
            return jsonify(success=False, message='无法确定计算方案：%s' % sim_policy)
        # need config
        month = int(request.form.get(u'试算月份'))
        with open('incentivepower/conf/%s_sim_form.json' % company_name, 'rb') as sim_form_file:
            sim_form = json.load(sim_form_file)
        if False and policy_id == '573eac648398a20009260940':  # 2016年Q2CV代表达成贡献奖
            sim_data, msg = _get_sim_data(policy_id,
                                          {'user_code': sim_user, 'tag': sim_tag},
                                          company_name,
                                          request.form.get(u'试算月份'))
            if sim_data:
                # need config
                # 确定试算方案后，指定一个既有的计算作为生成模拟计算的模板
                # 注意试算方案是否有依赖的预处理
                calc_template = db._find_one_in_org('Calculation',
                                                    # 2016年Q2CV代表产品捆绑：2016年4月
                                                    {'_id': ObjectId('574bdaabceb0e400093de55f')},
                                                    company_name)
                if not calc_template:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template['_id'] = 'n/a'
                calc_template['category'] = 'sim'
                calc_template['data_filter'] = {}
                # calc_template['hierarchy_source']['source'] = 'sim'
                # calc_template['kpi_map'] = {'sim': calc_template['kpi_map']['data']}
                sim_args = {'sim_meta': calc_template,
                            const.TASK_ARG_COMPANYNAME: company_name,
                            'sim_data': {calc_template['hierarchy_source']['id']: []}}
                # need config
                if sim_tag in sim_form.get(policy_id, {}):
                    form_data = sim_form[policy_id][sim_tag]
                    for sd in sim_data:
                        for fd in form_data:
                            if fd['type'] == 'static':
                                continue
                            sd[fd['value']] = request.form.get(u'%s%s' % (sd['YM'] if fd['label'].startswith('_') else '', fd['label']),
                                                               sd[fd['value']])
                        sim_args['sim_data'][calc_template['hierarchy_source']['id']].append(sd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (sim_tag, sim_policy['title']))
                # need config
                # 执行预处理，得到预处理结果后传入奖金计算方案
                result1 = execute_simulation(sim_args)
                calc_template1 = db._find_one_in_org('Calculation',
                                                     # 2016年Q2CV代表达成贡献奖：2016年4月
                                                     {'_id': ObjectId('574e13b1a1e68d000b82a779')},
                                                     company_name)
                if not calc_template1:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template1['_id'] = 'n/a'
                calc_template1['category'] = 'sim'
                calc_template1['data_filter'] = {}
                sim_args1 = {'sim_meta': calc_template1,
                             const.TASK_ARG_COMPANYNAME: company_name,
                             'sim_result': {calc_template1['hierarchy_source']['id']: result1}}
                final_result = execute_simulation(sim_args1)
                # need config
                display_cols = [u'在岗月份数', u'达成贡献奖', u'月均实际销售额', u'TAG标准人均生产力', u'贡献率系数', u'奖金基数',
                                u'产品1销量', u'产品1指标', u'产品1达成率', u'产品1A/T系数', u'产品1奖金权重',
                                u'产品2销量', u'产品2指标', u'产品2达成率', u'产品2A/T系数', u'产品2奖金权重',
                                u'结构内产品A/T']
                display_result = [{'label': u'试算方案', 'value': request.form.get(u'试算方案', 'N/A')},
                                  {'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                                  {'label': u'员工号', 'value': sim_user},
                                  {'label': u'TAG', 'value': sim_tag}]
                for dc in display_cols:
                    display_result.append({'label': dc, 'value': final_result[0].get(dc, 'n/a')})
                return jsonify(success=True, result=display_result)
            else:
                return jsonify(success=False, message=msg)
        elif policy_id == '5aa744c2139976000ddf106e': # 2018年BCBH代表达成贡献奖-模算
            uinfo = db.get_sim_hierarchy(user_id.upper(), company_name)
            sim_data, msg = _get_sim_data(policy_id,
                                          {'user_code': sim_user, 'tag': sim_tag, 'team':uinfo['team'].upper()},
                                          company_name,
                                          request.form.get(u'试算月份'))
            if sim_data:
                # need config
                # 确定试算方案后，指定一个既有的计算作为生成模拟计算的模板
                # 注意试算方案是否有依赖的预处理
                # 2018年BCBH代表产品捆绑-模拟:2018
                calc_id = '5acdcd2ad10327000d0ee538' if uinfo['team'].upper() == 'COUNTY' else '5aa7405613997600272bf559'
                calc_template = db._find_one_in_org('Calculation',
                                                    # 2018年BCBH代表产品捆绑-模拟：2018
                                                    {'_id': ObjectId(calc_id)},
                                                    company_name)
                if not calc_template:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template['_id'] = 'n/a'
                calc_template['category'] = 'sim'
                calc_template['data_filter'] = {}
                sim_args = {'sim_meta': calc_template,
                            const.TASK_ARG_COMPANYNAME: company_name,
                            'sim_data': {calc_template['hierarchy_source']['id']: []}}
                # need config
                if sim_tag in sim_form.get(policy_id, {}):
                    form_data = sim_form[policy_id][sim_tag]
                    for sd in sim_data:
                        for fd in form_data:
                            if fd['type'] == 'static':
                                continue
                            sd[fd['value']] = request.form.get(u'%s%s' % (sd['YM'] if fd['label'].startswith('_') else '', fd['label']),
                                                               sd[fd['value']])
                        sim_args['sim_data'][calc_template['hierarchy_source']['id']].append(sd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (sim_tag, sim_policy['title']))
                # need config
                # 执行预处理，得到预处理结果后传入奖金计算方案
                result1 = execute_simulation(sim_args)
                calc_id = '5acdcdbdd10327000cdb1e59' if uinfo['team'].upper() == 'COUNTY' else '5aa744ef1399760031ab1460'
                calc_template1 = db._find_one_in_org('Calculation',
                                                     # 2018年BCBH&County代表达成贡献奖-模拟：2018年
                                                     {'_id': ObjectId(calc_id)},
                                                     company_name)
                if not calc_template1:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template1['_id'] = 'n/a'
                calc_template1['category'] = 'sim'
                calc_template1['data_filter'] = {}

                sim_args1 = {'sim_meta': calc_template1,
                             const.TASK_ARG_OWNER: calc_template1.get('owner',''),
                             const.TASK_ARG_COMPANYNAME: company_name,
                             const.TASK_ARG_DATA_ENV: const.ENV_PRODUCTION,
                             'sim_result': {calc_template1['hierarchy_source']['id']: result1},
                             }
                final_result = execute_simulation(sim_args1)
                # need config
                display_cols = [u'在岗月份数', u'达成贡献奖', u'月均实际销售额', u'TAG标准人均生产力', u'贡献率系数', u'奖金基数',
                                u'产品1销量', u'产品1指标', u'产品1达成率', u'产品1A/T系数', u'产品1奖金权重',
                                u'产品2销量', u'产品2指标', u'产品2达成率', u'产品2A/T系数', u'产品2奖金权重',
                                u'产品3销量', u'产品3指标', u'产品3达成率', u'产品3A/T系数', u'产品3奖金权重',
                                u'结构内产品A/T', u'第一个策略产品A/T', u'第二个策略产品A/T', u'策略产品系数']
                display_result = [{'label': u'试算方案', 'value': request.form.get(u'试算方案', 'N/A')},
                                  {'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                                  {'label': u'K账号', 'value': sim_user},
                                  {'label': u'TAG', 'value': sim_tag}]
                for dc in display_cols:
                    this_val = final_result[0].get(dc, 'n/a')
                    if dc == u'达成贡献奖':
                        dc = u'YTD达成贡献奖'
                    if this_val != 'n/a':
                        if dc.endswith(u'奖') or dc.endswith(u'额') or dc.endswith(u'销量') or dc.endswith(
                                u'指标') or dc.endswith(u'系数'):
                            if dc == u'策略产品系数' and not this_val:
                                continue
                            display_result.append({'label': dc, 'value': lib.round2float(this_val)})
                        elif u'策略' in dc and this_val in [1.0, 0.0]:
                            continue
                        elif dc.endswith(u'达成率') or dc.endswith('A/T'):
                            display_result.append({'label': dc, 'value': '%d%%' % (lib.round2float(this_val) * 100)})
                        elif sim_tag == 'CVB' and dc == u'TAG标准人均生产力':
                            display_result.append({'label': dc, 'value': '-'})
                        else:
                            display_result.append({'label': dc, 'value': this_val})
                    else:
                        display_result.append({'label': dc, 'value': this_val})
                # TODO 计算已发, 在某月就显示到某月的已发。到四月就显示1-4月的已发
                paid_value = 0
                display_result.append({'label': 'YTD已发', 'value': paid_value})
                for r in display_result:
                    if u'产品1' in r['label']:
                        r['color'] = ''
                    elif u'产品2' in r['label']:
                        r['color'] = 'deep_purple'
                    elif u'产品3' in r['label']:
                        r['color'] = ''
                    else:
                        r['color'] = 'deep_blue'
                return jsonify(success=True, result=display_result, show_products=True)
            else:
                return jsonify(success=False, message=msg)
        elif policy_id == '5aa74591139976002c3c7aee': # 2018年BCBH代表增长奖-模算
            uinfo = db.get_sim_hierarchy(user_id.upper(), company_name)
            sim_data, msg = _get_sim_data(policy_id,
                                          {'user_code': sim_user, 'tag': sim_tag, 'team':uinfo['team'].upper()},
                                          company_name,
                                          request.form.get(u'试算月份'))
            if sim_data:
                # need config
                # 确定试算方案后，指定一个既有的计算作为生成模拟计算的模板
                # 注意试算方案是否有依赖的预处理
                calc_id = '5acdce84d10327000d0ee53b' if uinfo['team'].upper() == 'COUNTY' else '5aa745e61399760031ab1462'
                calc_template = db._find_one_in_org('Calculation',
                                                     # 2018年BCBH&County代表增长奖-模拟：2018年
                                                     {'_id': ObjectId(calc_id)},
                                                     company_name)
                if not calc_template:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template['_id'] = 'n/a'
                calc_template['category'] = 'sim'
                calc_template['data_filter'] = {}
                sim_args = {'sim_meta': calc_template,
                            const.TASK_ARG_COMPANYNAME: company_name,
                            'sim_data': {calc_template['hierarchy_source']['id']: []}}
                # need config
                if sim_tag in sim_form.get(policy_id, {}):
                    form_data = sim_form[policy_id][sim_tag]
                    for sd in sim_data:
                        for fd in form_data:
                            if fd['type'] == 'static':
                                continue
                            sd[fd['value']] = request.form.get(
                                u'%s%s' % (sd['YM'] if fd['label'].startswith('_') else '', fd['label']),
                                sd[fd['value']])
                        sim_args['sim_data'][calc_template['hierarchy_source']['id']].append(sd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (sim_tag, sim_policy['title']))
                final_result = execute_simulation(sim_args)
                # need config
                display_cols = [u'在岗月份数', u'标准增长奖金', u'额外增长奖金', u'最终增长奖金',
                                u'第一个策略产品A/T', u'第二个策略产品A/T', u'策略产品系数'
                                # u'结构内产品A/T', u'策略产品A/T'
                                ]
                display_result = [{'label': u'试算方案', 'value': request.form.get(u'试算方案', 'N/A')},
                                  {'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                                  {'label': u'K账号', 'value': sim_user},
                                  {'label': u'TAG', 'value': sim_tag}]
                for dc in display_cols:
                    this_val = final_result[0].get(dc, 'n/a')
                    if dc == u'标准增长奖金':
                        dc = u'YTD标准增长奖金'
                    if dc == u'额外增长奖金':
                        dc = u'YTD额外增长奖金'
                    if dc == u'最终增长奖金':
                        dc = u'YTD最终增长奖金'
                    if this_val != 'n/a':
                        if dc.endswith(u'奖金'):
                            display_result.append({'label': dc, 'value': lib.round2float(this_val)})
                        elif u'个策略' in dc and this_val in [1.0, 0.0]:
                            continue
                        elif dc == u'策略产品系数' and not this_val:
                            display_result.append({'label': dc, 'value': this_val})
                        elif dc.endswith('A/T'):
                            display_result.append({'label': dc, 'value': '%d%%' % (lib.round2float(this_val) * 100)})
                        else:
                            display_result.append({'label': dc, 'value': this_val})
                    else:
                        display_result.append({'label': dc, 'value': this_val})
                # TODO 计算已发, 在某月就显示到某月的已发。到四月就显示1-4月的已发
                paid_value = 0
                display_result.append({'label': 'YTD已发', 'value': paid_value})
                return jsonify(success=True, result=display_result)
            else:
                return jsonify(success=False, message=msg)
        elif policy_id == '59ae589de9c6a300349edc53': # 2017年BCBH代表达成贡献奖-模算
            sim_data, msg = _get_sim_data(policy_id,
                                          {'user_code': sim_user, 'tag': sim_tag},
                                          company_name,
                                          request.form.get(u'试算月份'))
            if sim_data:
                # need config
                # 确定试算方案后，指定一个既有的计算作为生成模拟计算的模板
                # 注意试算方案是否有依赖的预处理
                calc_template = db._find_one_in_org('Calculation',
                                                    # 2017年BCBH代表产品捆绑-模算：2017年H1模拟计算
                                                    {'_id': ObjectId('59ae562ee9c6a3002e9b1766')},
                                                    company_name)
                if not calc_template:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template['_id'] = 'n/a'
                calc_template['category'] = 'sim'
                calc_template['data_filter'] = {}
                sim_args = {'sim_meta': calc_template,
                            const.TASK_ARG_COMPANYNAME: company_name,
                            'sim_data': {calc_template['hierarchy_source']['id']: []}}
                # need config
                if sim_tag in sim_form.get(policy_id, {}):
                    form_data = sim_form[policy_id][sim_tag]
                    for sd in sim_data:
                        for fd in form_data:
                            if fd['type'] == 'static':
                                continue
                            sd[fd['value']] = request.form.get(u'%s%s' % (sd['YM'] if fd['label'].startswith('_') else '', fd['label']),
                                                               sd[fd['value']])
                        sim_args['sim_data'][calc_template['hierarchy_source']['id']].append(sd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (sim_tag, sim_policy['title']))
                # need config
                # 执行预处理，得到预处理结果后传入奖金计算方案
                result1 = execute_simulation(sim_args)
                calc_template1 = db._find_one_in_org('Calculation',
                                                     # 2017年BCBH代表达成贡献奖-模算：2017年1月
                                                     {'_id': ObjectId('59ae58dbe9c6a300349edcf1')},
                                                     company_name)
                if not calc_template1:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template1['_id'] = 'n/a'
                calc_template1['category'] = 'sim'
                calc_template1['data_filter'] = {}

                sim_args1 = {'sim_meta': calc_template1,
                             const.TASK_ARG_COMPANYNAME: company_name,
                             'sim_result': {calc_template1['hierarchy_source']['id']: result1},
                             }
                final_result = execute_simulation(sim_args1)
                # need config
                display_cols = [u'在岗月份数', u'达成贡献奖', u'月均实际销售额', u'TAG标准人均生产力', u'贡献率系数', u'奖金基数',
                                u'产品1销量', u'产品1指标', u'产品1达成率', u'产品1A/T系数', u'产品1奖金权重',
                                u'产品2销量', u'产品2指标', u'产品2达成率', u'产品2A/T系数', u'产品2奖金权重',
                                u'产品3销量', u'产品3指标', u'产品3达成率', u'产品3A/T系数', u'产品3奖金权重',
                                u'结构内产品A/T', u'第一个策略产品A/T', u'第二个策略产品A/T', u'策略产品系数']
                display_result = [{'label': u'试算方案', 'value': request.form.get(u'试算方案', 'N/A')},
                                  {'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                                  {'label': u'K账号', 'value': sim_user},
                                  {'label': u'TAG', 'value': sim_tag}]
                for dc in display_cols:
                    this_val = final_result[0].get(dc, 'n/a')
                    if dc == u'达成贡献奖':
                        dc = u'YTD达成贡献奖'
                    if this_val != 'n/a':
                        if dc.endswith(u'奖') or dc.endswith(u'额') or dc.endswith(u'销量') or dc.endswith(
                                u'指标') or dc.endswith(u'系数'):
                            if dc == u'策略产品系数' and not this_val:
                                continue
                            display_result.append({'label': dc, 'value': lib.round2float(this_val)})
                        elif u'策略' in dc and this_val in [1.0, 0.0]:
                            continue
                        elif dc.endswith(u'达成率') or dc.endswith('A/T'):
                            display_result.append({'label': dc, 'value': '%d%%' % (lib.round2float(this_val) * 100)})
                        elif sim_tag == 'CVB' and dc == u'TAG标准人均生产力':
                            display_result.append({'label': dc, 'value': '-'})
                        else:
                            display_result.append({'label': dc, 'value': this_val})
                    else:
                        display_result.append({'label': dc, 'value': this_val})
                # TODO 计算已发, 在某月就显示到某月的已发。到四月就显示1-4月的已发
                paid_value = 0
                # 6月已发
                if month >= 201706:
                    paid = db.get_payout('59792d11c07acc000d34ef2a', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('59792d11c07acc000d34ef2a', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv

                # 5月已发
                if month >= 201705:
                    paid = db.get_payout('594c90884dfd18000bc6842a', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('594c90884dfd18000bc6842a', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                # 4月已发
                if month >= 201704:
                    paid = db.get_payout('591d42bd4fcec9000d534943', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('591d42bd4fcec9000d534943', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                # 3月已发
                elif month >= 201703:
                    paid = db.get_payout('59001a4ca3875c000a981904', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('59001a4ca3875c000a981904', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                # 2月已发
                elif month >= 201702:
                    paid = db.get_payout('58d0ac43f9eece01000327dc', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('58d0ac43f9eece01000327dc', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                # 1月已发
                elif month >= 201701:
                    paid = db.get_payout('58b7bfe99426ce002e54add0', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                display_result.append({'label': 'YTD已发', 'value': paid_value})
                for r in display_result:
                    if u'产品1' in r['label']:
                        r['color'] = ''
                    elif u'产品2' in r['label']:
                        r['color'] = 'deep_purple'
                    elif u'产品3' in r['label']:
                        r['color'] = 'green'
                    else:
                        r['color'] = 'deep_blue'
                return jsonify(success=True, result=display_result, show_products=True)
            else:
                return jsonify(success=False, message=msg)
        elif policy_id == '59ae58a5e9c6a300349edc84': # 2017年BCBH代表增长奖-模算
            user_data = []
            sim_data, msg = _get_sim_data(policy_id,
                                          {'user_code': sim_user, 'tag': sim_tag},
                                          company_name,
                                          request.form.get(u'试算月份'))
            if sim_data:
                # need config
                # 确定试算方案后，指定一个既有的计算作为生成模拟计算的模板
                # 注意试算方案是否有依赖的预处理
                calc_template = db._find_one_in_org('Calculation',
                                                     # 2017年BCBH代表增长奖-模算：2017年H1模算
                                                     {'_id': ObjectId('59ae596ce9c6a3002e9b1769')},
                                                     company_name)
                if not calc_template:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template['_id'] = 'n/a'
                calc_template['category'] = 'sim'
                calc_template['data_filter'] = {}
                sim_args = {'sim_meta': calc_template,
                            const.TASK_ARG_COMPANYNAME: company_name,
                            'sim_data': {calc_template['hierarchy_source']['id']: []}}
                # need config
                if sim_tag in sim_form.get(policy_id, {}):
                    form_data = sim_form[policy_id][sim_tag]
                    for sd in sim_data:
                        for fd in form_data:
                            if fd['type'] == 'static':
                                continue
                            sd[fd['value']] = request.form.get(
                                u'%s%s' % (sd['YM'] if fd['label'].startswith('_') else '', fd['label']),
                                sd[fd['value']])
                        sim_args['sim_data'][calc_template['hierarchy_source']['id']].append(sd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (sim_tag, sim_policy['title']))
                final_result = execute_simulation(sim_args)
                # need config
                display_cols = [u'在岗月份数', u'标准增长奖金', u'额外增长奖金', u'最终增长奖金',
                                u'第一个策略产品A/T', u'第二个策略产品A/T', u'策略产品系数'
                                # u'结构内产品A/T', u'策略产品A/T'
                                ]
                display_result = [{'label': u'试算方案', 'value': request.form.get(u'试算方案', 'N/A')},
                                  {'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                                  {'label': u'K账号', 'value': sim_user},
                                  {'label': u'TAG', 'value': sim_tag}]
                for dc in display_cols:
                    this_val = final_result[0].get(dc, 'n/a')
                    if dc == u'标准增长奖金':
                        dc = u'YTD标准增长奖金'
                    if dc == u'额外增长奖金':
                        dc = u'YTD额外增长奖金'
                    if dc == u'最终增长奖金':
                        dc = u'YTD最终增长奖金'
                    if this_val != 'n/a':
                        if dc.endswith(u'奖金'):
                            display_result.append({'label': dc, 'value': lib.round2float(this_val)})
                        elif u'个策略' in dc and this_val in [1.0, 0.0]:
                            continue
                        elif dc == u'策略产品系数' and not this_val:
                            display_result.append({'label': dc, 'value': this_val})
                        elif dc.endswith('A/T'):
                            display_result.append({'label': dc, 'value': '%d%%' % (lib.round2float(this_val) * 100)})
                        else:
                            display_result.append({'label': dc, 'value': this_val})
                    else:
                        display_result.append({'label': dc, 'value': this_val})
                # TODO 计算已发, 在某月就显示到某月的已发。到四月就显示1-4月的已发
                paid_value = 0
                # 6月已发
                if month >= 201706:
                    paid = db.get_payout('591d42bd4fcec9000d534943', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('591d42bd4fcec9000d534943', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                # 5月已发
                if month >= 201705:
                    paid = db.get_payout('594c90884dfd18000bc6842a', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('594c90884dfd18000bc6842a', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                # 4月已发
                if month >= 201704:
                    paid = db.get_payout('591d42bd4fcec9000d534943', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('591d42bd4fcec9000d534943', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                # 3月已发
                elif month >= 201703:
                    paid = db.get_payout('59001a4ca3875c000a981904', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('59001a4ca3875c000a981904', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                # 2月已发
                elif month >= 201702:
                    paid = db.get_payout('58d0ac43f9eece01000327dc', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('58d0ac43f9eece01000327dc', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                # 1月已发
                elif month >= 201701:
                    paid = db.get_payout('58b7bfe99426ce002e54add0', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                display_result.append({'label': 'YTD已发', 'value': paid_value})
                return jsonify(success=True, result=display_result)
            else:
                return jsonify(success=False, message=msg)
        elif policy_id == '58abf09628112c000ae0b8d2': # 2017年County代表销售绩效奖-模算

            sim_data, msg = _get_sim_data(policy_id,
                                          {'user_code': sim_user, 'tag': sim_tag},
                                          company_name,
                                          request.form.get(u'试算月份'))
            if sim_data:
                # need config
                # 确定试算方案后，指定一个既有的计算作为生成模拟计算的模板
                # 注意试算方案是否有依赖的预处理
                calc_template = db._find_one_in_org('Calculation',
                                                    # 2017年County代表销售绩效奖-模算：2017年H1模拟计算
                                                    {'_id': ObjectId('58abf0be28112c000ae0b90a')},
                                                    company_name)
                if not calc_template:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template['_id'] = 'n/a'
                calc_template['category'] = 'sim'
                calc_template['data_filter'] = {}
                sim_args = {'sim_meta': calc_template,
                            const.TASK_ARG_COMPANYNAME: company_name,
                            'sim_data': {calc_template['hierarchy_source']['id']: []}}

                # need config
                if sim_tag in sim_form.get(policy_id, {}):
                    form_data = sim_form[policy_id][sim_tag]
                    for sd in sim_data:
                        for fd in form_data:
                            if fd['type'] == 'static' or not fd['label'].startswith('_'):
                                continue
                            sd[fd['value']] = request.form.get(u'%s%s' % (sd['YM'], fd['label']),
                                                               sd[fd['value']])
                        sim_args['sim_data'][calc_template['hierarchy_source']['id']].append(sd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (sim_tag, sim_policy['title']))
                # need config
                final_result = execute_simulation(sim_args)
                # need config
                # display_cols = [u'在岗月份数', u'达成奖', u'增长奖', u'产品销量', u'产品指标', u'产品去年销量',
                #                 u'产品达成率', u'产品A/T系数', u'达成奖基数', u'增长系数', u'策略系数',
                #                 u'AS团队YTD完成率', u'AS系数']
                display_cols = [u'在岗月份数', u'达成奖', u'增长奖', u'产品达成率' u'达成奖基数',
                                u'CVM总销量', u'CVM总指标', u'CVM去年销量', u'CVM增长系数', u'CVM净增长金额',
                                u'GI总销量', u'GI总指标', u'GI去年销量', u'GI增长系数', u'GI净增长金额',
                                u'CVM+GI达成率', u'CVM+GI奖金权重', u'CVM+GI-A/T系数',
                                u'RIA总销量', u'RIA总指标', u'RIA去年销量', u'RIA达成率', u'RIA-A/T系数', u'RIA奖金权重',
                                u'RIA增长系数', u'RIA净增长金额',
                                u'Onco总销量', u'Onco总指标', u'Onco去年销量', u'Onco达成率', u'Onco-A/T系数', u'Onco奖金权重',
                                u'Onco增长系数', u'Onco净增长金额',
                                ]
                display_result = [{'label': u'试算方案', 'value': request.form.get(u'试算方案', 'N/A')},
                                  {'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                                  {'label': u'K账号', 'value': sim_user},
                                  {'label': u'TAG', 'value': sim_tag}]
                for dc in display_cols:
                    this_val = final_result[0].get(dc, 'n/a')
                    if dc == u'达成奖':
                        dc = u'YTD达成奖'
                    if dc == u'增长奖':
                        dc = u'YTD增长奖'
                    if this_val != 'n/a':
                        if dc.endswith(u'奖') or dc.endswith(u'销量') or dc.endswith(u'指标') or dc.endswith(u'系数'):
                            display_result.append({'label': dc, 'value': lib.round2float(this_val)})
                        elif dc.endswith(u'达成率') or dc.endswith(u'完成率'):
                            display_result.append({'label': dc, 'value': '%d%%' % (lib.round2float(this_val) * 100)})
                        else:
                            display_result.append({'label': dc, 'value': this_val})
                    else:
                        display_result.append({'label': dc, 'value': this_val})
                # TODO 计算已发, 在某月就显示到某月的已发。到四月就显示1-4月的已发
                paid_value = 0
                if month >= 201706:
                    # 6月达成已发
                    paid = db.get_payout('597a9fe2d34d8d000c0cbced', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('597a9fe2d34d8d000c0cbced', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    # 6月达成已发
                    paid = db.get_payout('597a9fe2d34d8d000c0cbced', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('597a9fe2d34d8d000c0cbced', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                if month >= 201705:
                    # 5月达成已发
                    paid = db.get_payout('5950e1f25a83cd0028b9ccd3', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('5950e1f25a83cd0028b9ccd3', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    # 5月达成已发
                    paid = db.get_payout('5950e1f25a83cd0028b9ccd3', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('5950e1f25a83cd0028b9ccd3', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                if month >= 201704:
                    # 4月达成已发
                    paid = db.get_payout('591e649e4fcec900405a8077', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('591e649e4fcec900405a8077', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    # 4月增长已发
                    paid = db.get_payout('591e649e4fcec900405a8077', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('591e649e4fcec900405a8077', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                elif month >= 201703:
                    # 3月达成已发
                    paid = db.get_payout('58ff289d9286f2000ce63998', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('58ff289d9286f2000ce63998', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    # 3月增长已发
                    paid = db.get_payout('58ff289d9286f2000ce63998', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('58ff289d9286f2000ce63998', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                elif month >= 201702:
                    # 2月达成已发
                    paid = db.get_payout('58d0e56cb39aa9000a9b5a28', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('58d0e56cb39aa9000a9b5a28', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    # 2月增长已发
                    paid = db.get_payout('58d0e56cb39aa9000a9b5a28', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'YTD已发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    paid = db.get_payout('58d0e56cb39aa9000a9b5a28', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                elif month >= 201701:
                    # 1月达成已发
                    paid = db.get_payout('58b62f85e680d0002edfc9c3', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发达成奖', company_name)
                    for pv in paid:
                        paid_value += pv
                    # 1月增长已发
                    paid = db.get_payout('58b62f85e680d0002edfc9c3', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月实发增长奖', company_name)
                    for pv in paid:
                        paid_value += pv
                display_result.append({'label': 'YTD已发', 'value': paid_value})
                return jsonify(success=True, result=display_result)
            else:
                return jsonify(success=False, message=msg)


        elif policy_id == '57a8cd3cc558f5000aac3f17':  # 2016年H2BCBH代表达成贡献奖
            sim_data, msg = _get_sim_data(policy_id,
                                          {'user_code': sim_user, 'tag': sim_tag},
                                          company_name,
                                          request.form.get(u'试算月份'))
            if sim_data:
                # need config
                # 确定试算方案后，指定一个既有的计算作为生成模拟计算的模板
                # 注意试算方案是否有依赖的预处理
                calc_template = db._find_one_in_org('Calculation',
                                                    # 2016年H2BCBH代表产品捆绑：2016年H2模拟计算
                                                    {'_id': ObjectId('57a8c954c558f5002c2f91c3')},
                                                    company_name)
                if not calc_template:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template['_id'] = 'n/a'
                calc_template['category'] = 'sim'
                calc_template['data_filter'] = {}
                # calc_template['hierarchy_source']['source'] = 'sim'
                # calc_template['kpi_map'] = {'sim': calc_template['kpi_map']['data']}
                sim_args = {'sim_meta': calc_template,
                            const.TASK_ARG_COMPANYNAME: company_name,
                            'sim_data': {calc_template['hierarchy_source']['id']: []}}
                # need config
                if sim_tag in sim_form.get(policy_id, {}):
                    form_data = sim_form[policy_id][sim_tag]
                    for sd in sim_data:
                        for fd in form_data:
                            if fd['type'] == 'static':
                                continue
                            sd[fd['value']] = request.form.get(u'%s%s' % (sd['YM'] if fd['label'].startswith('_') else '', fd['label']),
                                                               sd[fd['value']])
                        sim_args['sim_data'][calc_template['hierarchy_source']['id']].append(sd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (sim_tag, sim_policy['title']))
                # need config
                # 执行预处理，得到预处理结果后传入奖金计算方案
                result1 = execute_simulation(sim_args)
                calc_template1 = db._find_one_in_org('Calculation',
                                                     # 2016年H2BCBH达成贡献奖：2016年H2模拟计算
                                                     {'_id': ObjectId('57a8d214c558f5002c2f91c5')},
                                                     company_name)
                if not calc_template1:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template1['_id'] = 'n/a'
                calc_template1['category'] = 'sim'
                calc_template1['data_filter'] = {}
                sim_args1 = {'sim_meta': calc_template1,
                             const.TASK_ARG_COMPANYNAME: company_name,
                             'sim_result': {calc_template1['hierarchy_source']['id']: result1}}
                final_result = execute_simulation(sim_args1)
                # need config
                display_cols = [u'在岗月份数', u'达成贡献奖', u'月均实际销售额', u'TAG标准人均生产力', u'贡献率系数', u'奖金基数',
                                u'产品1销量', u'产品1指标', u'产品1达成率', u'产品1A/T系数', u'产品1奖金权重',
                                u'产品2销量', u'产品2指标', u'产品2达成率', u'产品2A/T系数', u'产品2奖金权重',
                                u'产品3销量', u'产品3指标', u'产品3达成率', u'产品3A/T系数', u'产品3奖金权重',
                                u'结构内产品A/T', u'策略产品A/T']
                display_result = [{'label': u'试算方案', 'value': request.form.get(u'试算方案', 'N/A')},
                                  {'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                                  {'label': u'K账号', 'value': sim_user},
                                  {'label': u'TAG', 'value': sim_tag}]
                for dc in display_cols:
                    this_val = final_result[0].get(dc, 'n/a')
                    if dc == u'达成贡献奖':
                        dc = u'YTD达成贡献奖'
                    if this_val != 'n/a':
                        if dc.endswith(u'奖') or dc.endswith(u'额') or dc.endswith(u'销量') or dc.endswith(u'指标') or dc.endswith(u'系数'):
                            display_result.append({'label': dc, 'value': lib.round2float(this_val)})
                        elif dc.endswith(u'达成率') or dc.endswith('A/T'):
                            display_result.append({'label': dc, 'value': '%d%%' % (lib.round2float(this_val) * 100)})
                        else:
                            display_result.append({'label': dc, 'value': this_val})
                    else:
                        display_result.append({'label': dc, 'value': this_val})
                # 计算已发
                paid_value = 0
                # 7月已发
                paid = db.get_payout('57c93eae2022c800272d261f', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 8月已发
                paid = db.get_payout('57ea3a18389dca0009e9f7a4', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 9月已发
                paid = db.get_payout('5815d3c112dcdc000dc3569d', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 10月已发
                paid = db.get_payout('583ec91a1c0874000c90647c', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 11月已发
                paid = db.get_payout('586231832aad3e000b13290f', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 12月已发
                paid = db.get_payout('58876e8e4cffb8002845cd36', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv

                display_result.append({'label': 'YTD已发', 'value': paid_value})
                return jsonify(success=True, result=display_result, show_products=True)
            else:
                return jsonify(success=False, message=msg)
        elif policy_id == '57a8d32dc558f500316898a2':  # 2016年H2BCBH代表增长奖
            user_data = []
            sim_data, msg = _get_sim_data(policy_id,
                                          {'user_code': sim_user, 'tag': sim_tag},
                                          company_name,
                                          request.form.get(u'试算月份'))
            if sim_data:
                # need config
                # 确定试算方案后，指定一个既有的计算作为生成模拟计算的模板
                # 注意试算方案是否有依赖的预处理
                if False and sim_tag in ('CVK', 'CVC', 'CVX'):
                    calc_template = db._find_one_in_org('Calculation',
                                                        # 2016年Q2CV代表产品捆绑：2016年4月
                                                        {'_id': ObjectId('574bdaabceb0e400093de55f')},
                                                        company_name)
                else:
                    calc_template = db._find_one_in_org('Calculation',
                                                        # 2016年H2BCBH代表产品捆绑：2016年H2模拟计算
                                                        {'_id': ObjectId('57a8c954c558f5002c2f91c3')},
                                                        company_name)
                if not calc_template:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template['_id'] = 'n/a'
                calc_template['category'] = 'sim'
                calc_template['data_filter'] = {}
                # calc_template['hierarchy_source']['source'] = 'sim'
                # calc_template['kpi_map'] = {'sim': calc_template['kpi_map']['data']}
                sim_args = {'sim_meta': calc_template,
                            const.TASK_ARG_COMPANYNAME: company_name,
                            'sim_data': {calc_template['hierarchy_source']['id']: []}}
                # need config
                if sim_tag in sim_form.get(policy_id, {}):
                    form_data = sim_form[policy_id][sim_tag]
                    for sd in sim_data:
                        for fd in form_data:
                            if fd['type'] == 'static':
                                continue
                            sd[fd['value']] = request.form.get(u'%s%s' % (sd['YM'] if fd['label'].startswith('_') else '', fd['label']),
                                                               sd[fd['value']])
                        user_data.append(sd)
                    sim_args['sim_data'][calc_template['hierarchy_source']['id']] = user_data
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (sim_tag, sim_policy['title']))
                # need config
                # 执行预处理，得到预处理结果后传入奖金计算方案
                result1 = execute_simulation(sim_args)
                if False and sim_tag in ('CVC', 'CVK', 'CVX'):
                    calc_template1 = db._find_one_in_org('Calculation',
                                                         # 2016年BCBH增长奖：2016年4月CV
                                                         {'_id': ObjectId('574f0f574797980031482920')},
                                                         company_name)
                else:
                    calc_template1 = db._find_one_in_org('Calculation',
                                                         # 2016年H2BCBH增长奖：2016年H2模拟计算
                                                         {'_id': ObjectId('57a8d7b2c558f50036047e7e')},
                                                         company_name)
                if not calc_template1:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template1['_id'] = 'n/a'
                calc_template1['category'] = 'sim'
                calc_template1['data_filter'] = {}
                sim_args1 = {'sim_meta': calc_template1,
                             const.TASK_ARG_COMPANYNAME: company_name,
                             'sim_data': {calc_template1['hierarchy_source']['id']: user_data},
                            #  'sim_result': {calc_template1['result_source'][0]: result1}
                             }
                final_result = execute_simulation(sim_args1)
                # need config
                display_cols = [u'在岗月份数', u'标准增长奖金', u'额外增长奖金', u'最终增长奖金',
                                # u'结构内产品A/T', u'策略产品A/T'
                                ]
                display_result = [{'label': u'试算方案', 'value': request.form.get(u'试算方案', 'N/A')},
                                  {'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                                  {'label': u'K账号', 'value': sim_user},
                                  {'label': u'TAG', 'value': sim_tag}]
                for dc in display_cols:
                    this_val = final_result[0].get(dc, 'n/a')
                    if dc == u'标准增长奖金':
                        dc = u'YTD标准增长奖金'
                    if dc == u'额外增长奖金':
                        dc = u'YTD额外增长奖金'
                    if dc == u'最终增长奖金':
                        dc = u'YTD最终增长奖金'
                    if this_val != 'n/a':
                        if dc.endswith(u'奖金'):
                            display_result.append({'label': dc, 'value': lib.round2float(this_val)})
                        elif dc.endswith('A/T'):
                            display_result.append({'label': dc, 'value': '%d%%' % (lib.round2float(this_val) * 100)})
                        else:
                            display_result.append({'label': dc, 'value': this_val})
                    else:
                        display_result.append({'label': dc, 'value': this_val})
                # 计算已发
                paid_value = 0
                # 7月已发
                paid = db.get_payout('57c93e8fecae1d0022b6965d', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 8月已发
                paid = db.get_payout('57ea3a35c30889000d62ec3c', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 9月已发
                paid = db.get_payout('5815c4cb12dcdc000dc33cd7', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 10月已发
                paid = db.get_payout('583eb97b1c0874000da113e4', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 11月已发
                paid = db.get_payout('586230f02aad3e000e1e4750', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 12月已发
                paid = db.get_payout('58876eed4cffb8000b107efe', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                display_result.append({'label': 'YTD已发', 'value': paid_value})
                return jsonify(success=True, result=display_result)
            else:
                return jsonify(success=False, message=msg)
        elif policy_id == '573d588f447de7000bf259c2':  # 2016年County代表销售绩效奖
            sim_data, msg = _get_sim_data(policy_id,
                                          {'user_code': sim_user, 'tag': sim_tag},
                                          company_name,
                                          request.form.get(u'试算月份'))
            if sim_data:
                # need config
                # 确定试算方案后，指定一个既有的计算作为生成模拟计算的模板
                # 注意试算方案是否有依赖的预处理
                calc_template = db._find_one_in_org('Calculation',
                                                    # 2016年County代表销售绩效奖：2016年5月
                                                    {'_id': ObjectId('57725a9841f4dd002c15dce0')},
                                                    company_name)
                if not calc_template:
                    return jsonify(success=False, message='获取计算模板失败。')
                calc_template['_id'] = 'n/a'
                calc_template['category'] = 'sim'
                calc_template['data_filter'] = {}
                sim_args = {'sim_meta': calc_template,
                            const.TASK_ARG_COMPANYNAME: company_name,
                            'sim_data': {calc_template['hierarchy_source']['id']: [],
                                         # need config
                                         '109': [{'EMPLOYEE_ADKEY': sim_user.upper(), 'KPI': request.form.get(u'AS团队YTD完成率')}]}}
                # need config
                if sim_tag in sim_form.get(policy_id, {}):
                    form_data = sim_form[policy_id][sim_tag]
                    for sd in sim_data:
                        for fd in form_data:
                            if fd['type'] == 'static' or not fd['label'].startswith('_'):
                                continue
                            sd[fd['value']] = request.form.get(u'%s%s' % (sd['YM'], fd['label']),
                                                               sd[fd['value']])
                        sim_args['sim_data'][calc_template['hierarchy_source']['id']].append(sd)
                else:
                    return jsonify(success=False, message='TAG与奖金方案不匹配：[%s][%s]' % (sim_tag, sim_policy['title']))
                # need config
                final_result = execute_simulation(sim_args)
                # need config
                display_cols = [u'在岗月份数', u'达成奖', u'增长奖', u'产品销量', u'产品指标', u'产品去年销量',
                                u'产品达成率', u'产品A/T系数', u'达成奖基数', u'增长系数', u'策略系数',
                                u'AS团队YTD完成率', u'AS系数']
                display_result = [{'label': u'试算方案', 'value': request.form.get(u'试算方案', 'N/A')},
                                  {'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                                  {'label': u'K账号', 'value': sim_user},
                                  {'label': u'TAG', 'value': sim_tag}]
                for dc in display_cols:
                    this_val = final_result[0].get(dc, 'n/a')
                    if dc == u'达成奖':
                        dc = u'YTD达成奖'
                    if dc == u'增长奖':
                        dc = u'YTD增长奖'
                    if this_val != 'n/a':
                        if dc.endswith(u'奖') or dc.endswith(u'销量') or dc.endswith(u'指标') or dc.endswith(u'系数'):
                            display_result.append({'label': dc, 'value': lib.round2float(this_val)})
                        elif dc.endswith(u'达成率') or dc.endswith(u'完成率'):
                            display_result.append({'label': dc, 'value': '%d%%' % (lib.round2float(this_val) * 100)})
                        else:
                            display_result.append({'label': dc, 'value': this_val})
                    else:
                        display_result.append({'label': dc, 'value': this_val})
                # 计算已发
                paid_value = 0
                # 7月达成已发
                paid = db.get_payout('57c7c7448d1a7700226fa637', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 7月增长已发
                paid = db.get_payout('57c7bf198d1a7700226fa5f8', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 8月达成已发
                paid = db.get_payout('57ea5bf4389dca000b500cce', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 8月增长已发
                paid = db.get_payout('57ea4d23c308890022815ecb', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 9月达成已发
                paid = db.get_payout('5815de3ef5cb4800092a94c1', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 9月增长已发
                paid = db.get_payout('5815dc5512dcdc000c82e66e', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 10月达成已发
                paid = db.get_payout('584016a0eead7d000aea79f1', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 10月增长已发
                paid = db.get_payout('5840459feead7d00280a65f7', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 11月达成已发
                paid = db.get_payout('5865cb3a71843b000a87a008', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 11月增长已发
                paid = db.get_payout('5865cd7971843b000b60189c', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 12月达成已发
                paid = db.get_payout('58940329178232002877fc15', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                # 12月增长已发
                paid = db.get_payout('5893ffbc178232002877fc13', {'data.员工号': sim_user, 'data.TAG': sim_tag}, u'当月应发', company_name)
                for pv in paid:
                    paid_value += pv
                display_result.append({'label': 'YTD已发', 'value': paid_value})
                return jsonify(success=True, result=display_result)
            else:
                return jsonify(success=False, message=msg)
        else:
            return jsonify(success=False, message='该方案尚未支持模拟计算：%s' % policy_id)
    elif company_name == 'saike':
        # 设置数据库类型
        env = const.ENV_SANDBOX
        color1 = '#F9BB28' # 黄色
        color2 = '#92D050' # 浅绿色
        color3 = '#00B0F0' # 蓝色
        # 处理输入基础数据
        file_list = [u'大区', u'办事处',
                     u'员工工号', u'中文姓名', u'员工姓名', u'绩效期间',
                     # u'考核分类',u'本季度任务', u'考核类型',
                       u'前4季度平均销量']
        input_data = {}
        for file in file_list:
            if request.form.get(file):
                input_data[file] = request.form.get(file)
        # 员工计算
        if request.form.get(u'考核分数') is None:
            # 执行员工绩效考核得分-模拟计算
            sql = "select * from \"%s\" t1 where t1.\"员工工号\"='%s'" % \
                  (_get_data_file_file_id('员工数据', company_name, env=env), user_id)
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败：%s' % r.json().get('message', '未知错误。'))
            calc_template0 = db._find_one_in_org('Calculation',
                                                # 员工绩效考核得分-模拟计算:2017Q1
                                                {'_id': ObjectId('5954c07441d92b000e70c78d')},
                                                company_name)
            if not calc_template0:
                return jsonify(success=False, message='获取计算模板失败。')
            version_ids = calc_template0[u'data_version']
            calc_data0 = r.json()['data']  # 员工绩效考核得分-模拟计算数据
            # 替换为输入数据
            sell_sum = 0
            medicine_type = []  # 品规列表
            for key in request.form.keys():
                if str(key).endswith(u'本季度流向'):
                    if str(key).split(u'本季度流向')[0] and request.form.get(key, u'0') != u'0':
                        medicine_type.append(str(key).split(u'本季度流向')[0])
                        sell_sum += float(request.form.get(key, 0))
            if not medicine_type:
                return jsonify(success=False, message='获取品规失败。')
            sim_result = [{u'临床人员工号':calc_data0[0].get(u'员工工号'), u'本季度流向':sell_sum,
                           u'本季度任务':request.form.get(u'本季度任务', 0),
                           u'前4季度平均销量':request.form.get(u'前4季度平均销量', 0)}]
            # 计算模板修正
            calc_template0['_id'] = 'n/a'
            calc_template0['category'] = 'sim'
            calc_template0['data_filter'] = {}
            sim_args0 = {'sim_meta': calc_template0,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': {calc_template0['hierarchy_source']['id']: calc_data0},
                         'sim_result': {calc_template0['result_source'][0]: sim_result}}
            result0 = execute_simulation(sim_args0)  # 结果
            if isinstance(result0, str):
                return jsonify(success=False, message=result0)
            # 执行 临床绩效-模拟计算
            # 获取计算模板
            calc_template1 = db._find_one_in_org('Calculation',
                                                 # 临床绩效-模拟计算：2017Q1
                                                 {'_id': ObjectId('5954c6db41d92b000a224355')},
                                                 company_name)
            if not calc_template1:
                return jsonify(success=False, message='获取计算模板失败。')
            version_ids = calc_template1[u'data_version']
            # 获取架构数据
            sql = ("select * from \"%s\" where \"员工工号\"='%s' ") % (
                      _get_data_file_file_id('汇报关系数据', company_name, env=env),
                      user_id
                  )
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败：%s' % r.json().get('message', '未知错误。'))
            # 替换为输入数据
            calc_data1 = []
            base_data1 = r.json()['data']
            for m_type in medicine_type:
                base_data1[0][u'品规'] = m_type
                base_data1[0][u'本季度流向'] = request.form.get(u"%s本季度流向" % m_type, 0)
                calc_data1.append(base_data1[0].copy())
            # 获取一般数据
            normal_data1 = {}
            file_version_id, file_file_id = _get_data_file_version_id_and_file_id('绩效政策数据', company_name, version_ids, env=env)
            sql = ("select * from \"%s\" where \"办事处/地区\"='%s' ") % (
                # _get_data_file_file_id('绩效政策数据', company_name, env=env),
                file_file_id,
                base_data1[0][u'办事处/地区']
            )
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败：%s' % r.json().get('message', '未知错误。'))
            normal_data1.update({str(file_version_id):r.json()['data']})

            file_version_id, file_file_id = _get_data_file_version_id_and_file_id('季度平均供货价数据', company_name, version_ids, env=env)
            sql = ("select * from \"%s\" where \"办事处/地区\"='%s' ") % (
                file_file_id,
                base_data1[0][u'办事处/地区']
            )
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败：%s' % r.json().get('message', '未知错误。'))
            normal_data1.update({str(file_version_id): r.json()['data']})

            # file_version_id, file_file_id = _get_data_file_version_id_and_file_id('办事处考核类型', company_name, version_ids, env=env)
            # sql = ("select * from \"%s\" where \"办事处\"='%s' ") % (
            #     file_file_id,
            #     base_data1[0][u'办事处']
            # )
            # api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            # r = requests.post(api_url, data={'sql': sql})
            # if not (r.status_code == 200 and r.json().get('success', False)):
            #     return jsonify(success=False, message='身份验证失败：%s' % r.json().get('message', '未知错误。'))
            # normal_data1.update({str(file_version_id): r.json()['data']})
            # 计算模板修正
            calc_template1['_id'] = 'n/a'
            calc_template1['category'] = 'sim'
            calc_template1['data_filter'] = {}
            # 组装计算所需全部数据
            # 动态读取所需数据
            sim_data = {calc_template1['hierarchy_source']['id']: calc_data1}
            sim_data.update(normal_data1)
            sim_args1 = {'sim_meta': calc_template1,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': sim_data,
                         'sim_result': {calc_template1['result_source'][0]: result0}}
            result1 = execute_simulation(sim_args1)
            if isinstance(result1, str):
                return jsonify(success=False, message=result1)
            # 输出结果
            data = [{'label': file if file != u'考核分类' else u'人员分类',
                     'value': request.form.get(file), 'color': color1} for file in file_list[0:10] if
                     request.form.get(file) is not None]
            # if request.form.get(u'考核类型') == u'完成率':
            data.append({'label': u'本季度销量合计', 'value': sum([re.get(u'本季度流向') for re in result1]), 'color': color2})
            data.append({'label': u'本季度任务', 'value': request.form.get(u'本季度任务'), 'color': color2})
            data.append({'label': u'完成率', 'value': u"%.2f%%" % (result1[0].get(u'完成率') * 100), 'color': color3})
            # elif request.form.get(u'考核类型') == u'增长率':
            #     data.append({'label': u'环比', 'value': u"%.2f%%" % result1[0].get(u'环比'), 'color': color2})
            #     data.append({'label': u'本季度销量合计', 'value': sum([re.get(u'本季度流向') for re in result1]), 'color': color2})
            #     data.append({'label': u'前4季度平均销量', 'value': result0[0].get(u'前4季度平均销量'), 'color': color2})
            data.append({'label': u'销售结果得分', 'value': result1[0].get(u'销售结果得分'), 'color': color2})
            data.append({'label': u'销售行为得分', 'value': result1[0].get(u'销售行为得分'), 'color': color2})
            data.append({'label': u'考核分数A', 'value': result1[0].get(u'考核分数'), 'color': color3})
            data.append({'label': u'绩效基数和', 'value': sum([re.get(u'绩效基数') for re in result1]), 'color': color3})
            data.append({'label': u'绩效金额和', 'value': sum([re.get(u'绩效金额') for re in result1]), 'color': color3})
            for re in result1:
                m_type = re.get(u'品规', '')
                data.append({'label': u'品规', 'value': m_type, 'color': color2})
                data.append({'label': u'本季度销量', 'value': re.get(u'本季度流向'), 'color': color2})
                data.append({'label': u'价格', 'value': re.get(u'价格'), 'color': color2})
                data.append({'label': u'绩效基数A', 'value': re.get(u'绩效基数'), 'color': color2})
                data.append({'label': u'考核分数A', 'value': re.get(u'考核分数'), 'color': color2})
                data.append({'label': u'绩效金额A', 'value': re.get(u'绩效金额'), 'color': color2})
            # 最终返回
            return jsonify(success=True, data=data)
        # 经理计算
        else:
            # 获取模板
            calc_template0 = db._find_one_in_org('Calculation',
                                                 # 经理/主管绩效-模拟计算:2017Q1
                                                 {'_id': ObjectId('5954cad341d92b000b40e93e')},
                                                 company_name)
            if not calc_template0:
                return jsonify(success=False, message='获取计算模板失败。')
            version_ids = calc_template0[u'data_version']
            # 获取架构数据
            sql = ("select * from \"%s\" where \"员工工号\"='%s'") % \
                  (
                      _get_data_file_file_id('经理主管数据', company_name, env=env),
                      user_id
                  )
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败：%s' % r.json().get('message', '未知错误。'))
            base_data0 = r.json()['data']
            calc_data0 = []
            # 替换为输入数据
            for key in request.form.keys():
                if str(key).endswith(u'销量'):
                    m_type = str(key).split(u'销量')[0]
                    if m_type and request.form.get(key, u'0') != u'0':
                        base_data0[0][u'品规'] = m_type
                        base_data0[0][u'流向'] = request.form.get(key, 0)
                        base_data0[0][u'考核分数'] = request.form.get(u"考核分数")
                        calc_data0.append(base_data0[0].copy())
            # 获取一般数据
            normal_data0 = {}

            file_version_id, file_file_id = _get_data_file_version_id_and_file_id('季度平均供货价数据', company_name, version_ids, env=env)
            sql = ("select * from \"%s\" where \"办事处/地区\"='%s'") % \
                  (
                      file_file_id,
                      base_data0[0][u'办事处/地区']
                  )
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败：%s' % r.json().get('message', '未知错误。'))
            normal_data0.update({str(file_version_id): r.json()['data']})

            file_version_id, file_file_id = _get_data_file_version_id_and_file_id('领导思尔明绩效比例', company_name, version_ids, env=env)
            sql = ("select * from \"%s\" where \"员工工号\"='%s'") % \
                  (
                      file_file_id,
                      user_id
                  )
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败：%s' % r.json().get('message', '未知错误。'))
            normal_data0.update({str(file_version_id): r.json()['data']})

            file_version_id, file_file_id = _get_data_file_version_id_and_file_id('领导季度绩效比例', company_name, version_ids, env=env)
            sql = ("select * from \"%s\" where \"员工工号\"='%s'") % \
                  (
                      file_file_id,
                      user_id
                  )
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, env)
            r = requests.post(api_url, data={'sql': sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='身份验证失败：%s' % r.json().get('message', '未知错误。'))
            normal_data0.update({str(file_version_id): r.json()['data']})
            # 修正计算模板
            calc_template0['_id'] = 'n/a'
            calc_template0['category'] = 'sim'
            calc_template0['data_filter'] = {}
            # 组装计算所需全部数据
            # TODO:动态读取数据
            sim_data = {calc_template0['hierarchy_source']['id']: calc_data0}
            sim_data.update(normal_data0)
            # 生成引擎所需数据
            sim_args0 = {'sim_meta': calc_template0,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': sim_data}
            # 执行计算
            result0 = execute_simulation(sim_args0)
            # 返回结果
            data = [{'label': file, 'value': request.form.get(file), 'color': color1} for file in file_list if
                    request.form.get(file) is not None]
            data.append({'label': u'销量合计', 'value': sum([re.get(u'销量') for re in result0]), 'color': color3})
            data.append({'label': u'考核分数', 'value': re.get(u'考核分数'), 'color': color3})
            data.append({'label': u'经理主管绩效基数合计', 'value': sum([re.get(u'经理主管绩效基数') for re in result0]), 'color': color3})
            data.append({'label': u'绩效金额合计', 'value': sum([re.get(u'绩效金额') for re in result0]), 'color': color3})
            for re in result0:
                m_type = re.get(u'品规', '')
                data.append({'label': u'品规', 'value': m_type, 'color': color2})
                data.append({'label': u'销量', 'value': re.get(u'销量'), 'color': color2})
                data.append({'label': u'考核分数', 'value': re.get(u'考核分数'), 'color': color2})
                data.append({'label': u'经理主管绩效基数', 'value': re.get(u'经理主管绩效基数'), 'color': color2})
                data.append({'label': u'绩效金额', 'value': re.get(u'绩效金额'), 'color': color2})
            # 最终返回
            return jsonify(success=True, data=data)

    elif company_name == 'hisunpfizer':
        # need config
        use_tbl, use_quarter = _get_sim_source_table('', company_name)
        sim_quarter = request.form.get(u'季度', 'n/a')
        sim_bu = request.form.get('BU', 'n/a')
        if sim_bu == 'ONC':
            sim_bu = 'ON'
        sql = "select * from \"%s\" where \"ntid\"='%s' and \"quarter\"='%s' and \"bucode\" = '%s'" % \
                  (use_tbl, user_id, sim_quarter, sim_bu)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': sql})
        if r.status_code == 200 and r.json().get('success', False):
            sim_data = r.json().get('data', [])
            if not sim_data:
                return jsonify(success=False, message='找不到计算数据：%s %s %s' % (user_id, sim_quarter, sim_bu))
            # 做成用户数据
            all_sales = 0
            user_data = []
            product_data = {}
            agg_history = []
            # 先把package和product的从属关系取出来
            for sd in sim_data:
                product_name = sd['strengthname'] if not sd['strengthname'] else sd['strengthname'].strip()
                package_name = sd['packageName'] if not sd['packageName'] else sd['packageName'].strip()
                if not product_name or not package_name:
                    continue
                if product_name not in product_data:
                    product_data[product_name] = {'packages': {}}
                if package_name not in product_data[product_name]['packages']:
                    this_price, cmt = lib.cast2float(sd['packagePrice'])
                    if cmt:
                        return jsonify(success=False, message=cmt)
                    product_data[product_name]['packages'][package_name] = this_price
            sim_product_data = []
            for sd in sim_data:
                pname = sd['strengthname'] if not sd['strengthname'] else sd['strengthname'].strip()
                if not pname:
                    continue
                # 同一个产品只保留一行数据，在这行数据上对销量做汇总
                if pname in agg_history:
                    continue
                agg_history.append(pname)
                sd['productamount'] = 0
                for pkg in product_data[pname]['packages']:
                    this_quantity, cmt = lib.cast2float(request.form.get(('%s销量' % pkg).replace(' ', '_').replace('.', '_'), None))
                    # print pkg, this_quantity, product_data[pname]['packages'][pkg]
                    if cmt:
                        return jsonify(success=False, message=cmt)
                    sd['productamount'] += (this_quantity * product_data[pname]['packages'][pkg])
                # print '+++++++++', pname, sd['productamount']
                all_sales += sd['productamount']
                sim_product_data.append(sd)
            # print '|||||||', all_sales
            for sd in sim_product_data:
                sd['positionamount'] = all_sales
                user_data.append(sd)
            # 预处理
            # need config
            calc_template0 = db._find_one_in_org('Calculation',
                                                 # 数据预处理：代表增长奖：2016Q1New
                                                 {'_id': ObjectId('577a4a44ae871a000c00f9db')},
                                                 company_name)
            if not calc_template0:
                return jsonify(success=False, message='获取计算模板失败。')
            calc_template0['_id'] = 'n/a'
            calc_template0['category'] = 'sim'
            calc_template0['data_filter'] = {}
            sim_args0 = {'sim_meta': calc_template0,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': {calc_template0['hierarchy_source']['id']: user_data}}
            # need config
            # 执行预处理，得到预处理结果后传入奖金计算方案
            result0 = execute_simulation(sim_args0)

            calc_template1 = db._find_one_in_org('Calculation',
                                                 # 数据预处理：按产品计算销量：2016Q1New
                                                 {'_id': ObjectId('577a4abdae871a00315f7289')},
                                                 company_name)
            if not calc_template1:
                return jsonify(success=False, message='获取计算模板失败。')
            calc_template1['_id'] = 'n/a'
            calc_template1['category'] = 'sim'
            calc_template1['data_filter'] = {}
            sim_args1 = {'sim_meta': calc_template1,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': {calc_template1['hierarchy_source']['id']: user_data}}
            # need config
            # 执行预处理，得到预处理结果后传入奖金计算方案
            result1 = execute_simulation(sim_args1)
            calc_template2 = db._find_one_in_org('Calculation',
                                                 # 数据预处理：按岗位计算销量：2016Q1New
                                                 {'_id': ObjectId('577a4bd3ae871a00315f728b')},
                                                 company_name)
            if not calc_template2:
                return jsonify(success=False, message='获取计算模板失败。')
            calc_template2['_id'] = 'n/a'
            calc_template2['category'] = 'sim'
            calc_template2['data_filter'] = {}
            sim_args2 = {'sim_meta': calc_template2,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': {calc_template2['hierarchy_source']['id']: user_data},
                         'sim_result': {calc_template2['result_source'][0]: result1}}
            # need config
            # 执行预处理，得到预处理结果后传入奖金计算方案
            result2 = execute_simulation(sim_args2)
            calc_template3 = db._find_one_in_org('Calculation',
                                                 # 奖金计算：2016代表增长奖：2016Q1New
                                                 {'_id': ObjectId('577a4f06ae871a00315f728d')},
                                                 company_name)
            if not calc_template3:
                return jsonify(success=False, message='获取计算模板失败。')
            calc_template3['_id'] = 'n/a'
            calc_template3['category'] = 'sim'
            calc_template3['data_filter'] = {}
            sim_args3 = {'sim_meta': calc_template3,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': {calc_template3['hierarchy_source']['id']: user_data},
                         'sim_result': {calc_template3['result_source'][0]: result0}}
            # need config
            # 执行预处理，得到预处理结果后传入奖金计算方案
            result3 = execute_simulation(sim_args3)
            calc_template4 = db._find_one_in_org('Calculation',
                                                #  # 奖金计算：2016代表完成奖：2016Q1New
                                                #  {'_id': ObjectId('577a521cae871a0027963ba1')},
                                                 # 奖金计算：2017代表完成奖：2017UAT
                                                 {'_id': ObjectId('586c5191cbfe160046abea6e')},
                                                 company_name)
            if not calc_template4:
                return jsonify(success=False, message='获取计算模板失败。')
            calc_template4['_id'] = 'n/a'
            calc_template4['category'] = 'sim'
            calc_template4['data_filter'] = {}
            sim_args4 = {'sim_meta': calc_template4,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': {calc_template4['hierarchy_source']['id']: user_data},
                         'sim_result': {calc_template4['result_source'][0]: result2}}
            # need config
            # 执行预处理，得到预处理结果后传入奖金计算方案
            result4 = execute_simulation(sim_args4)
            return jsonify(success=True, name=result4[0][u'员工姓名'],
                           data=[{'label': '总指标', 'value': result2[0][u'按岗位指标'], 'bold': False, 'is_percent': False},
                                 {'label': '总销量', 'value': result2[0][u'按岗位销量'], 'bold': False, 'is_percent': False},
                                 {'label': '达成率', 'value': result2[0][u'达成率'], 'bold': False, 'is_percent': True},
                                 {'label': '完成奖', 'value': result4[0][u'完成奖'], 'bold': False, 'is_percent': False},
                                 # 2017年没有增长奖
                                #  {'label': '增长奖', 'value': result3[0][u'增长奖'], 'bold': False, 'is_percent': False},
                                #  {'label': '基本奖总计', 'value': result4[0][u'完成奖']+result3[0][u'增长奖'], 'bold': True, 'is_percent': False}
                                  ])
        else:
            return jsonify(success=False, message='获取计算数据失败：%s[错误码:%d]' % (r.json().get('message', '未知错误'), r.status_code))
    elif company_name == 'bayer':
        sql = "select * from \"%s\" where \"MRCode\"='%s'" % \
              (_get_sim_source_table('', company_name), user_id)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': sql})
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message='身份验证失败[8]：%s' % r.json().get('message', '未知错误。'))
        sim_data = r.json().get('data', [])
        if sim_data:
            calc_template = db._find_one_in_org('Calculation',
                                                # 2016年Q1BHP销售达成奖-ForBiddingDemo：代表
                                                {'_id': ObjectId('57e1e7d6ba0624000bdb5763')},
                                                company_name)
            if not calc_template:
                return jsonify(success=False, message='获取计算模板失败。')
            calc_template['_id'] = 'n/a'
            calc_template['category'] = 'sim'
            calc_template['data_filter'] = {}
            sim_args = {'sim_meta': calc_template,
                        const.TASK_ARG_COMPANYNAME: company_name,
                        'sim_data': {   calc_template['hierarchy_source']['id']: [],
                                  }
                    }
            form_data = [{'label': '全产品销量', 'value': 'AllSalesAmount', 'type': 'number'},
                         {'label': 'Bayaspirin销量', 'value': 'B_SalesAmount', 'type': 'number'},
                         {'label': 'Adalat30mg销量', 'value': 'A 30mg*7_SalesAmount', 'type': 'number'},
                         {'label': 'Adalat60mg销量', 'value': 'A 60mg_SalesAmount', 'type': 'number'},
                     ]
            for sd in sim_data:
                for fd in form_data:
                    sd[fd['value']] = request.form.get(u'%s月%s' % (sd['Month'], fd['label']),
                                                        sd[fd['value']])
                sim_args['sim_data'][calc_template['hierarchy_source']['id']].append(sd)
            final_result = execute_simulation(sim_args)
            display_cols = [u'全产品指标', u'全产品销量',
                            u'全产品达成率', u'达成系数', u'全国人均指标', u'生产力', u'生产力系数', u'捆绑系数',
                            u'合规惩罚系数', u'达成奖基数', u'在岗月份', u'达成奖']
            display_result = [{'label': u'员工姓名', 'value': request.form.get(u'员工姓名', 'N/A')},
                              {'label': u'IPIN', 'value': request.form.get(u'IPIN', 'N/A')},
                              {'label': u'职位', 'value': request.form.get(u'职位', 'N/A')},
                              {'label': u'产品线', 'value': request.form.get(u'产品线', 'N/A')},
                              {'label': u'岗位号', 'value': request.form.get(u'TerritoryCode', 'N/A')},
                              {'label': u'岗位名称', 'value': request.form.get(u'TerritoryName', 'N/A')},
                              {'label': u'代岗', 'value': request.form.get(u'代岗', 'N/A')},
                            ]
            for dc in display_cols:
                display_result.append({'label': dc, 'value': final_result[0].get(dc, 'n/a')})
            return jsonify(success=True, result=display_result)
        else:
            return jsonify(success=False, message='找不到模拟数据。')
    elif company_name == 'bcs':
        data = {}
        calc_template = db._find_one_in_org('Calculation',
                                            # 2018BCS奖金
                                            {'_id': ObjectId('5ab9b633dbcb6a002c39b62d')},
                                            company_name)
        form_data = json.loads(request.get_data())
        if not form_data:
            return jsonify(success=False, message='无法获取表单数据')
        for field in form_data.get('data', []):
            data[field['label']] = field['value']
        sim_calc_data = [{
            u"员工号": "BCS_SIM",
            u"员工级别": data.get(u"员工级别", "E07"),
            u"月工资": data.get(u"员工工资", 1),
            u"上岗月份": data.get(u"入职时间", 1),
            u"时间段": data.get(u"绩效考核周期", "Q1"),
            u"全年消耗指标": data.get(u"全年消耗指标", 1),
            u"全产品实际消耗": data.get(u"全产品实际消耗", 1),
            u"全产品消耗指标": data.get(u"全产品季度消耗指标", 1),
            u"战略产品消耗指标": data.get(u"战略产品季度消耗指标", 1),
            u"战略产品实际消耗": data.get(u"战略产品实际消耗", 1),
            u"种衣剂实际消耗": data.get(u"种衣剂实际消耗", 1),
            u"种衣剂去年同期消耗": data.get(u"种衣剂去年同期消耗", 1),
            u"康帅妥消耗": data.get(u"康帅妥实际消耗", 1),
            u"种子消耗": data.get(u"种子实际消耗", 1),
            u"2017实际消耗": data.get(u"2017年同期实际消耗", 1),
            u"拿敌稳实际消耗": data.get(u"拿敌稳实际消耗", 1),
            u"拿敌稳消耗指标": data.get(u"拿敌稳消耗指标", 1),
        }]
        calc_template['_id'] = 'n/a'
        calc_template['category'] = 'sim'
        calc_template['data_filter'] = {}
        calc_sim_args = {'sim_meta': calc_template,
                           const.TASK_ARG_COMPANYNAME: company_name,
                           'sim_data': {calc_template['hierarchy_source']['id']: sim_calc_data}}
        direct_final_result = execute_simulation(calc_sim_args)
        if direct_final_result == 'finish':
            return jsonify(success=False, data={}, message="数据格式有误，计算错误！")
        return jsonify(success=True, data=direct_final_result[0], message="")
    elif company_name == 'kaniontest':
        user_info = {
            'name': '唐莉莉',
            'user_code': 'TLL1801',
            'level': 'REP',
            'bu': '主品种'
        }
        user_id = user_info['user_code']
        policy_id = request.form.get('policy_id', '')
        sim_policy_calc = {
            "5b711d717409a3000c7e1ba6": "5b716e413ae876000a2167fb",
        }
        policy_ignore_field = {
            '5b711d717409a3000c7e1ba6': [
                u"销售片区", u"省公司", u"办事处", u"购入客户", u"品种简称", u"终端品种", u"购入责任人工号", u"购入责任人姓名",
                u"医院分类", u"产品类型", u"产品线", u"主体", u"考核分类", u"Q2数量", u"Q2消化金额", u"考核金额(扣减返利)",
                u"费用考核金额(中标0_dot_93)", u"兑现计提费用额", u"2017年均值标准", u"考核均值分类", u"2018年计划金额",
                u"2017年同期金额", u"兑现标准", u"终端完成率", u"代表整体计划金额", u"代表整体达成金额", u"代表整体完成率",
                u"考核兑现标准", u"考核兑现金额", u"增幅兑现", u"发放兑现金额", u"分类", u"月均(含新开发)", u"是否新代表",
                u"是否环比增长", u"二季度兑现拉通发放", u"4月省公司", u"5月省公司", u"4月发放兑现", u"5月发放兑现", u"6月发放兑现"]
        }
        if sim_policy_calc[policy_id]:
            sim_calc_id = sim_policy_calc[policy_id]
        else:
            return jsonify(success=False, message="找不到对应的计算", data={})
        calc = db.get_calc_in_org(sim_calc_id, company_name)
        calc_template = db._find_one_in_org('Calculation',
                                            {'_id': ObjectId(sim_calc_id)},
                                            company_name)
        policy = db.get_policy_by_id(policy_id, calc['owner'])
        data_version = calc['hierarchy_source']['id']
        data_map = calc['kpi_map']['data'][data_version]
        r = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_VERSION_INFO, data_version), company_name, const.ENV_PRODUCTION))
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="无效的数据来源[0]", data={})
        file_file_id = r.json().get('data', {}).get('file_file_id', '')
        if not file_file_id:
            return jsonify(success=False, message="无效的数据来源[1]", data={})
        _sql_filter = " and ".join(["\"%s\"='%s'" % (data_map[u"购入责任人工号"], user_id)])
        _sql = "select * from \"{data_version}\" where {sql_filter}".format(data_version=file_file_id, sql_filter=_sql_filter)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': _sql})
        if not(r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="获取数据失败！", data={})
        source_data = r.json().get('data', [])
        if data_map:
            data = []
            for kpi in data_map:
                if data_map[kpi]:
                    data.append({'title': kpi, 'label': data_map.get(kpi),
                                 'value': source_data[0][data_map[kpi]],
                                 'type': 'static'})
        else:
            return jsonify(success=False, message="获取数据失败！", data={})
        data_simcalc = {}
        for i in range(0, len(data)):
            data_simcalc[data[i].get('label')] = data[i].get('value')
        data=[data_simcalc]
        rslt = db.get_calc_result(sim_calc_id, calc['owner'])
        if rslt and rslt.get('result', []):
            rslt_data = rslt['result']
            if policy.get('result_columns', []):
                header = []
                for k in policy['result_columns']:
                    if k in rslt_data[0] and k not in header and not k == '_id':
                        header.append(k)
                for k in rslt_data[0]:
                    if k not in header and not k == '_id':
                        header.append(k)
            else:
                header = [k for k in rslt_data[0] if not k == '_id']
        else:
            rslt_data = []
            header = []
        if not request.form.keys():
            return jsonify(success=False, message='无法获取表单数据')
        for key in request.form.keys():
            data[0][key] = request.form.get(key, '')
        calc_template['_id'] = 'n/a'
        calc_template['category'] = 'sim'
        calc_template['data_filter'] = {}
        calc_sim_args = {'sim_meta': calc_template,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': {calc_template['hierarchy_source']['id']: data}}
        direct_final_result = execute_simulation(calc_sim_args)
        if direct_final_result == 'finish':
            return jsonify(success=False, data={}, message="数据格式有误，计算错误！")
        sim_rslt_data = []
        for r in direct_final_result:
            for kpi in policy_ignore_field[policy_id]:
                if r.get(kpi) is None:
                    continue
                sim_rslt_data.append({'title': kpi, 'label': kpi,
                                      'value': str(r[kpi]) if not type(r[kpi]) in (int, float, long) else \
                                          format(float('%.2f' % float(r[kpi])), ',')})
            return jsonify(success=True, message="", data=sim_rslt_data)
        else:
            return jsonify(success=False, message="获取数据失败！", data={})
    elif company_name == 'gvtest':
        user_info = db.get_sim_hierarchy(user_id, company_name)
        user_position = user_info['terr_id']
        user_id = user_info['user_code']
        policy_id = request.form.get('policy_id', '')
        sim_policy_calc = {
            '5b70ec1a3119a00081b41cec': '5b70f5343119a00081b41cf1'
        }
        policy_ignore_field = {
            '5b70ec1a3119a00081b41cec': [u'员工号', u'员工姓名', u'季度纯销销量', u'季度纯销指标', u'季度纯销达成率',
                                         u'是否达到起奖线', u'单支提成奖金', u'岗位季度达成奖', u'是否冻结奖金']
        }
        formulas = {
            u"伟素-省区&销售": u"岗位季度达成奖 =<br>季度纯销销量 × 单支提成奖金",
        }
        if sim_policy_calc[policy_id]:
            sim_calc_id = sim_policy_calc[policy_id]
        else:
            return jsonify(success=False, message="找不到对应的计算", data={})
        calc = db.get_calc_in_org(sim_calc_id, company_name)
        calc_template = db._find_one_in_org('Calculation',
                                            {'_id': ObjectId(sim_calc_id)},
                                            company_name)
        policy = db.get_policy_by_id(policy_id, calc['owner'])
        data_version = calc['hierarchy_source']['id']
        data_map = calc['kpi_map']['data'][data_version]
        r = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_VERSION_INFO, data_version), company_name, const.ENV_PRODUCTION))
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="无效的数据来源[0]", data={})
        file_file_id = r.json().get('data', {}).get('file_file_id', '')
        if not file_file_id:
            return jsonify(success=False, message="无效的数据来源[1]", data={})
        _sql_filter = " and ".join(["\"%s\"='%s'" % (data_map[u"员工号"], user_id), "\"%s\"='%s'" % (data_map[u"岗位编码"], user_position)])
        # _sql_filter = "\"%s\"='%s'" % (data_map[u"员工号"], user_id)
        _sql = "select * from \"{data_version}\" where {sql_filter}".format(data_version=file_file_id, sql_filter=_sql_filter)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': _sql})
        if not(r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="获取数据失败！", data={})
        source_data = r.json().get('data', [])
        if data_map:
            data = []
            for kpi in data_map:
                if data_map[kpi]:
                    if '精细' in kpi:
                        data.append({'title': kpi, 'label': data_map.get(kpi),
                                     'value': source_data[0][data_map[kpi]],
                                     'type': 'select',
                                     'option': ["总代", "精细"]})
                    else:
                        data.append({'title': kpi, 'label': data_map.get(kpi),
                                     'value': source_data[0][data_map[kpi]],
                                     'type': 'static' if '销量' not in kpi or 'YTD发货指标' != kpi else 'number'})

        else:
            return jsonify(success=False, message="获取数据失败！", data={})
        data_simcalc = {}
        for i in range(0, len(data)):
            data_simcalc[data[i].get('label')] = data[i].get('value')
        data=[data_simcalc]
        rslt = db.get_calc_result(sim_calc_id, calc['owner'])
        if rslt and rslt.get('result', []):
            rslt_data = rslt['result']
            if policy.get('result_columns', []):
                header = []
                for k in policy['result_columns']:
                    if k in rslt_data[0] and k not in header and not k == '_id':
                        header.append(k)
                for k in rslt_data[0]:
                    if k not in header and not k == '_id':
                        header.append(k)
            else:
                header = [k for k in rslt_data[0] if not k == '_id']
        else:
            rslt_data = []
            header = []
        if not request.form.keys():
            return jsonify(success=False, message='无法获取表单数据')
        for key in request.form.keys():
            data[0][key] = request.form.get(key, '')
        calc_template['_id'] = 'n/a'
        calc_template['category'] = 'sim'
        calc_template['data_filter'] = {}
        calc_sim_args = {'sim_meta': calc_template,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': {calc_template['hierarchy_source']['id']: data}}
        direct_final_result = execute_simulation(calc_sim_args)
        if direct_final_result == 'finish':
            return jsonify(success=False, data={}, message="数据格式有误，计算错误！")
        # if header:
        #     for kpi in header:
        sim_rslt_data = []
        for r in direct_final_result:
            # if r[u'员工号'] == user_id:
            #     if r.get(kpi):
            # for kpi, rslt_value in r.items():
            for kpi in policy_ignore_field[policy_id]:
                if r.get(kpi) is None:
                    continue
                sim_rslt_data.append({'title': kpi, 'label': kpi,
                                      'value': str(r[kpi]) if not type(r[kpi]) in (int, float, long) else \
                                          format(float('%.2f' % float(r[kpi])), ',')})
                    #     else:
                    #         pass
                    # else:
                    #     pass
                    # break # 一圈退出
            for title in formulas:
                if title in policy['title']:
                    sim_rslt_data.append({'title': u'公式', 'label': u'公式', 'value': formulas[title]})
                    break
            sim_rslt_data.append({'title': u'备注', 'label': u'备注', 'value': '模拟器均根据全工时计算奖金'})
            return jsonify(success=True, message="", data=sim_rslt_data)
        else:
            return jsonify(success=False, message="获取数据失败！", data={})
    elif company_name == 'greenvalley':
        # TODO
        # 架构完成后换为真实用户
        user_info = db.get_sim_hierarchy(user_id, company_name)
        user_position = user_info['terr_id']
        user_id = user_info['user_code']
        # user_id, user_position = 'LGYY000000', 'MR_LGYY000000'
        # calc_id = request.form.get('calculation_id', '')
        policy_id = request.form.get('policy_id', '')
        sim_policy_calc = {
            '5aa8d518033bf50022b3b9dc': '5ad5b6bd7bdddb000a30980a',
            '5aa8e20c033bf5002c38b797': '5ad5ccea7bdddb000cf028c7',
            '5ab232f9ef90fc00317e2e85': '5ad5cfb67bdddb000bcd5e40',
            '5ab23ca8ef90fc00317e2e97': '5af1be939ccc52002c8223fe',
            '5ab24b4fef90fc00367909c3': '5ad6e0897bdddb005431c442',
            '5ad6e8287bdddb005efd905d': '5ae3c9924fac450009234a02',
            '5ae1efaed32066000c6ba115': '5ae80e0e7fe3fa000c48e6c0',
            '5ae1f39fd32066000d1f9e22': '5ae1f724d32066000d1f9e2d',
            '5ae3f8b8b577b4000aa921f6': '5ae3f92fb577b4000aa9221c',
            '5aeaaefaa5b5cc000990383c': '5aeab151a5b5cc003b36f832',
            '5aeaaffca5b5cc003622c57f': '5aeab3e7a5b5cc0009903854',
            '5b1dd908fa5f660022942024': '5b1ddb69fa5f660022942037',
            '5ab22b66ef90fc00277da84b': '5b28787eb29756000a10b258',
            '5ab24056ef90fc00317e2e9e': '5b287ba8b297560009a67365'
        }
        policy_ignore_field = {
            '5aa8d518033bf50022b3b9dc': [u'员工号', u'员工姓名', u'岗位编码', u'季度销量', u'季度指标', u'季度达成率',
                                         u'是否达到起奖线', u'达成系数', u'岗位季度达成奖', u'是否冻结奖金'],
            '5aa8e20c033bf5002c38b797': [u'员工号', u'员工姓名', u'岗位编码', u'季度销量', u'季度指标', u'季度达成率',
                                         u'是否达到起奖线', u'达成系数', u'岗位季度达成奖', u'连续达成季度数', u'连续达成奖金',
                                         u'岗位季度奖金', u'是否冻结奖金'],
            '5ab232f9ef90fc00317e2e85': [u'员工号', u'员工姓名', u'岗位编码', u'精细/总代', u'当季度纯销销量',
                                         u'当季度纯销指标', u'当季度纯销达成率', u'达成系数', u'去年纯销销量', u'同期增长率',
                                         u'增长系数', u'YTD发货销量', u'YTD发货指标', u'YTD发货达成率', u'是否达到起奖线',
                                         u'岗位季度达成奖', u'连续达成季度数', u'连续达成奖金', u'岗位季度奖金', u'是否冻结奖金'],
            '5ab23ca8ef90fc00317e2e97': [u'员工号', u'员工姓名', u'岗位编码', u'当季度纯销销量', u'当季度纯销指标',
                                         u'当季度纯销达成率', u'是否达到起奖线', u'岗位季度达成奖', u'是否冻结奖金'],
            '5ab24b4fef90fc00367909c3': [u'员工号', u'员工姓名', u'岗位编码', u'当季度纯销销量', u'当季度纯销指标',
                                         u'当季度纯销达成率', u'YTD发货销量', u'YTD发货指标', u'YTD发货达成率', u'奖金基数',
                                         u'是否达到起奖线', u'岗位季度达成奖', u'岗位季度奖金',
                                         u'是否冻结奖金'],
            '5ad6e8287bdddb005efd905d': [u'员工号', u'员工姓名', u'岗位编码', u'精细/总代', u'当季度纯销销量(不含民营)',
                                         u'当季度纯销指标(不含民营)', u'当季度纯销销量', u'当季度纯销指标',u'当季度纯销达成率',
                                         u'达成系数',
                                         u'去年纯销销量(不含民营)', u'同期增长率', u'增长系数', u'YTD发货销量', u'YTD发货指标',
                                         u'YTD发货达成率', u'是否达到起奖线', u'是否含有民营',  u'当季度民营纯销销量', u'当季度民营纯销指标',
                                         u'当季度民营纯销达成率',
                                         u'民营奖金', u'打折系数',
                                         u'岗位季度达成奖', u'连续达成季度数', u'连续达成奖金', u'岗位季度奖金',
                                         u'是否冻结奖金'],
            '5ae1efaed32066000c6ba115': [u'员工号', u'员工姓名', u'季度发货量', u'季度发货指标', u'季度发货达成率',
                                         u'奖金基数', u'岗位季度达成奖', u'是否冻结奖金'],
            '5ae1f39fd32066000d1f9e22': [u'员工号', u'员工姓名', u'季度纯销销量', u'季度纯销指标', u'季度纯销达成率',
                                         u'是否达到起奖线', u'单支提成奖金', u'岗位季度达成奖', u'是否冻结奖金'],
            '5ae3f8b8b577b4000aa921f6': [u'员工号', u'员工姓名', u'岗位编码', u'精细/总代', u'当季度纯销销量',
                                         u'当季度纯销指标', u'当季度纯销达成率', u'达成系数', u'去年纯销销量', u'同期增长率',
                                         u'增长系数', u'YTD发货销量', u'YTD发货指标', u'YTD发货达成率', u'是否达到起奖线',
                                         u'岗位季度达成奖', u'连续达成季度数', u'连续达成奖金', u'岗位季度奖金',
                                         u'是否冻结奖金'],
            '5aeaaefaa5b5cc000990383c': [u'员工号', u'员工姓名', u'岗位编码', u'季度销量', u'季度指标', u'季度达成率',
                                         u'是否达到起奖线', u'达成系数', u'岗位季度达成奖', u'是否冻结奖金'],
            '5aeaaffca5b5cc003622c57f': [u'员工号', u'员工姓名', u'季度纯销销量',u'季度纯销指标', u'季度纯销达成率',
                                         u'是否达到起奖线', u'单支提成奖金', u'岗位季度达成奖', u'是否冻结奖金'],
            '5b1dd908fa5f660022942024': [u'员工号', u'员工姓名', u'职务', u'季度纯销销量', u'季度纯销指标', u'季度纯销达成率',
                                         u'奖金基数', u'岗位季度达成奖'],
            '5ab22b66ef90fc00277da84b': [u'员工号', u'员工姓名', u'岗位编码', u"下属区域经理岗位数", u"P",
                                         u"下属岗位达成奖总和", u"季度总销量", u"季度总指标", u"大区经理", u"是否达到起奖线",
                                         u"季度达成率", u"连续达成季度数", u"连续达成奖金", u"岗位季度奖金"],
            '5ab24056ef90fc00317e2e9e': [u'员工号', u'员工姓名', u'岗位编码', u"当季度纯销销量(含民营)", u"当季度纯销指标(含民营)",
                                         u"当季度纯销达成率", u"YTD发货销量", u"YTD发货指标", u"YTD发货达成率",
                                         u"是否达到起奖线", u"是否含有民营", u"当季度民营纯销销量", u"当季度民营纯销指标",
                                         u"当季度民营纯销达成率", u"民营奖金", u"打折系数", u"下属招商岗位数", u"P",
                                         u"下属岗位达成奖总和", u"岗位季度达成奖", u"连续达成季度数", u"连续达成奖金",
                                         u"岗位季度奖金"]
        }
        formulas = {
            u"自营-医学信息沟通专员": u"岗位季度达成奖 =<br>(季度销量 × 单支奖金)<br>× 达成系数",
            u"自营-医学信息沟通专员(县域)": u"岗位季度达成奖 =<br>(季度销量 × 单支奖金)<br>× 达成系数",
            u"自营-区域经理": u"岗位季度达成奖 =<br>(季度销量 × 单支奖金)<br>× 达成系数 + 连续达成奖",
            u"招商福建经理/主管": u"岗位季度达成奖 =<br>当季度纯销销量 × 单支奖金",
            u"招商经理/主管": u"岗位季度达成奖 =<br>(当季度纯销销量 × 单支奖金)<br>× 达成系数 × 增长系数<br>+ 连续达成奖",
            u"民营&招商-大区(副)经理": u"岗位季度达成奖 =<br>(下属岗位达成奖总和<br>/ 下属岗位数 × P)<br>× 打折系数<br>+ (民营纯销销量 × 单支奖金)<br>+ 连续达成奖",
            u"民营-终端招商经理": u"岗位季度达成奖 =<br>当季度纯销销量 × 单支奖金",
            u"自营-大区经理": u"岗位季度达成奖 =<br>下属岗位达成奖总和 / 下属岗位数<br>× P <br> + 连续达成奖",
            u"销售总监": u"岗位季度达成奖 =<br>奖金基数<br>× (当季度纯销销量<br>/ 当季度纯销指标)",
            u"招商-李毅": u"岗位季度达成奖 =<br>非民营招商奖金+民营奖金=<br>(当季度非民营纯销销量<br>× 单支奖金 × 达成系数<br>× 增长系数 × 打折系数<br>+ 当季度民营纯销销量<br> × 单支奖金)<br> + 连续达成奖",
            u"伟素-总监": u"岗位季度达成奖 =<br>季度发货量 / 季度发货指标<br>× 奖金基数",
            u"伟素-大区经理": u"岗位季度达成奖 =<br>季度纯销销量 × 单支提成奖金",
            u"伟素-省区&销售": u"岗位季度达成奖 =<br>季度纯销销量 × 单支提成奖金",
            u"伟素-副总监": u"岗位季度达成奖 =<br>季度纯销销量 / 季度纯销指标<br>× 奖金基数"
        }
        if sim_policy_calc[policy_id]:
            sim_calc_id = sim_policy_calc[policy_id]
        else:
            return jsonify(success=False, message="找不到对应的计算", data={})
        calc = db.get_calc_in_org(sim_calc_id, company_name)
        calc_template = db._find_one_in_org('Calculation',
                                            {'_id': ObjectId(sim_calc_id)},
                                            company_name)
        policy = db.get_policy_by_id(policy_id, calc['owner'])
        data_version = calc['hierarchy_source']['id']
        data_map = calc['kpi_map']['data'][data_version]
        r = requests.get(lib.data_api('%s/%s' % (cfg.DATA_API_VERSION_INFO, data_version), company_name, const.ENV_PRODUCTION))
        if not (r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="无效的数据来源[0]", data={})
        file_file_id = r.json().get('data', {}).get('file_file_id', '')
        if not file_file_id:
            return jsonify(success=False, message="无效的数据来源[1]", data={})
        _sql_filter = " and ".join(["\"%s\"='%s'" % (data_map[u"员工号"], user_id), "\"%s\"='%s'" % (data_map[u"岗位编码"], user_position)])
        # _sql_filter = "\"%s\"='%s'" % (data_map[u"员工号"], user_id)
        _sql = "select * from \"{data_version}\" where {sql_filter}".format(data_version=file_file_id, sql_filter=_sql_filter)
        api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
        r = requests.post(api_url, data={'sql': _sql})
        if not(r.status_code == 200 and r.json().get('success', False)):
            return jsonify(success=False, message="获取数据失败！", data={})
        source_data = r.json().get('data', [])
        if data_map:
            data = []
            for kpi in data_map:
                if data_map[kpi]:
                    if '精细' in kpi:
                        data.append({'title': kpi, 'label': data_map.get(kpi),
                                     'value': source_data[0][data_map[kpi]],
                                     'type': 'select',
                                     'option': ["总代", "精细"]})
                    else:
                        data.append({'title': kpi, 'label': data_map.get(kpi),
                                     'value': source_data[0][data_map[kpi]],
                                     'type': 'static' if '销量' not in kpi or 'YTD发货指标' != kpi else 'number'})

        else:
            return jsonify(success=False, message="获取数据失败！", data={})
        data_simcalc = {}
        for i in range(0, len(data)):
            data_simcalc[data[i].get('label')] = data[i].get('value')
        data=[data_simcalc]
        rslt = db.get_calc_result(sim_calc_id, calc['owner'])
        if rslt and rslt.get('result', []):
            rslt_data = rslt['result']
            if policy.get('result_columns', []):
                header = []   
                for k in policy['result_columns']:
                    if k in rslt_data[0] and k not in header and not k == '_id':
                        header.append(k)
                for k in rslt_data[0]:
                    if k not in header and not k == '_id':
                        header.append(k)
            else:
                header = [k for k in rslt_data[0] if not k == '_id']
        else:
            rslt_data = []
            header = []
        if not request.form.keys():
            return jsonify(success=False, message='无法获取表单数据')
        for key in request.form.keys():
            data[0][key] = request.form.get(key, '')
        calc_template['_id'] = 'n/a'
        calc_template['category'] = 'sim'
        calc_template['data_filter'] = {}
        calc_sim_args = {'sim_meta': calc_template,
                         const.TASK_ARG_COMPANYNAME: company_name,
                         'sim_data': {calc_template['hierarchy_source']['id']: data}}
        if policy_id == '5ab22b66ef90fc00277da84b':
            subs_file_id = _get_data_file_file_id('模拟数据', company_name, table_name='自营-区域经理-for大区模拟器')
            _sql = "select * from \"%s\" where \"大区经理\"='%s' and \"大区经理岗位号\"='%s'" % (
                subs_file_id, data[0][u'员工号'], data[0][u'岗位编码']
            )
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
            r = requests.post(api_url, data={'sql': _sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='获取下属数据失败：%s' % r.json().get('message', '未知错误。'))
            sub_source_data = r.json().get('data', [])
            sub_data_rows = {}
            for sub in sub_source_data:
                sub_data_rows[sub[u'岗位编码']] = sub
            for i in range(1, len(sub_source_data) + 1):
                sub_data_rows[request.form.get('sub_area_%d' % i)][u'季度达成率'] = request.form.get('sub_rate_%s' % i)
            sub_calc_template = db._find_one_in_org('Calculation',
                                                {'_id': ObjectId('5b28781eb29756000a10b255')},
                                                company_name)
            sub_calc_template['_id'] = 'n/a'
            sub_calc_template['category'] = 'sim'
            sub_calc_template['data_filter'] = {}
            sub_calc_sim_args = {'sim_meta': sub_calc_template,
                                 const.TASK_ARG_COMPANYNAME: company_name,
                                 'sim_data': {sub_calc_template['hierarchy_source']['id']: sub_data_rows.values()}}
            sub_result = execute_simulation(sub_calc_sim_args)
            calc_sim_args['sim_result'] = {'5b28781eb29756000a10b255': sub_result}
        if policy_id == '5ab24056ef90fc00317e2e9e':
            subs_file_id = _get_data_file_file_id('模拟数据', company_name, table_name='招商经理/主管-for大区经理模拟器')
            _sql = "select * from \"%s\" where \"大区经理\"='%s' and \"大区经理岗位号\"='%s'" % (
                subs_file_id, source_data[0][u'员工号'], source_data[0][u'岗位编码']
            )
            api_url = lib.data_api(cfg.DATA_API_RUN_SQL, company_name, const.ENV_PRODUCTION)
            r = requests.post(api_url, data={'sql': _sql})
            if not (r.status_code == 200 and r.json().get('success', False)):
                return jsonify(success=False, message='获取下属数据失败：%s' % r.json().get('message', '未知错误。'))
            sub_source_data = r.json().get('data', [])
            sub_data_rows = {}
            for sub in sub_source_data:
                sub_data_rows[sub[u'岗位编码']] = sub
            for i in range(1, len(sub_source_data) + 1):
                sub_data_rows[request.form.get('sub_area_%d' % i)][u'当季度纯销达成率'] = request.form.get('sub_rate_%s' % i)
                sub_data_rows[request.form.get('sub_area_%d' % i)][u'同期增长率'] = request.form.get('sub_growth_%s' % i)
                sub_data_rows[request.form.get('sub_area_%d' % i)][u'YTD发货达成率'] = request.form.get('sub_send_%s' % i)
            sub_calc_template = db._find_one_in_org('Calculation',
                                                {'_id': ObjectId('5b287b5db29756000a10b281')},
                                                company_name)
            sub_calc_template['_id'] = 'n/a'
            sub_calc_template['category'] = 'sim'
            sub_calc_template['data_filter'] = {}
            sub_calc_sim_args = {'sim_meta': sub_calc_template,
                                 const.TASK_ARG_COMPANYNAME: company_name,
                                 'sim_data': {sub_calc_template['hierarchy_source']['id']: sub_data_rows.values()}}
            sub_result = execute_simulation(sub_calc_sim_args)
            calc_sim_args['sim_result'] = {'5b287b5db29756000a10b281': sub_result}
        direct_final_result = execute_simulation(calc_sim_args)
        if direct_final_result == 'finish':
            return jsonify(success=False, data={}, message="数据格式有误，计算错误！")
        # if header:
        #     for kpi in header:
        sim_rslt_data = []
        for r in direct_final_result:
            # if r[u'员工号'] == user_id:
            #     if r.get(kpi):
            # for kpi, rslt_value in r.items():
            for kpi in policy_ignore_field[policy_id]:
                if r.get(kpi) is None:
                    continue
                sim_rslt_data.append({'title': kpi, 'label': kpi,
                                      'value': str(r[kpi]) if not type(r[kpi]) in (int, float, long) else \
                                          format(float('%.2f' % float(r[kpi])), ',')})
                    #     else:
                    #         pass
                    # else:
                    #     pass
                    # break # 一圈退出
            for title in formulas:
                if title in policy['title']:
                    sim_rslt_data.append({'title': u'公式', 'label': u'公式', 'value': formulas[title]})
                    break
            sim_rslt_data.append({'title': u'备注', 'label': u'备注', 'value': '模拟器均根据全工时计算奖金'})
            return jsonify(success=True, message="", data=sim_rslt_data)
        else:
            return jsonify(success=False, message="获取数据失败！", data={})
        # return jsonify(success=True, data=direct_final_result[0], message="")


# 申诉
@app.route('/api/appeal/<calc_id>', methods=['POST'])
def api_appeal(calc_id):
    # 验证通过SSO登录的用户的JWT
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    time_cycle = db.get_setting_by_company(company_name)
    if company_name == 'cardinal':
        db.create_appeal(company_name, calc_id, user_id, request.form.get('comment', ''))
        return jsonify(success=True)
    elif company_name == 'bayer':
        db.create_appeal(company_name, calc_id, user_id, request.form.get('comment', ''))
        return jsonify(success=True)
    elif company_name == 'greenvalley' or company_name == 'gvtest':
        db.create_appeal_gv(company_name, user_id, request.form.get('comment', ''))
        return jsonify(success=True)
    elif company_name == 'uat':
        db.create_appeal(company_name, calc_id, user_id, request.form.get('comment', ''))
        return jsonify(success=True)
    else:
        return jsonify(success=False, message='该组织尚未支持申诉功能。')


@app.route('/api/appeal/update/<appeal_id>', methods=['POST'])
def update_appeal_status(appeal_id):
    ap = db.get_appeals_by_id(appeal_id,
                    session.get(const.SESSION_COMPANY[0], ''),)
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    if ap['status'] == '未处理':
        if not request.form.get('reply'):
            return jsonify(success=False, message='回复内容不能为空！')
        db.update_appeal(session.get(const.SESSION_COMPANY[0], ''),
                         appeal_id,
                         request.form.get('reply'),
                         ap['status']
                         )
    else:
        pass
    return jsonify(success=True, _csrf_token=generate_csrf_token())


@app.route('/api/appeal/list')
def api_appeal_list():
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    appeal_list = db.get_appeals_by_rep_id(user_id, company_name)
    data = []
    vaild_time = db.get_setting_by_company(company_name)
    now_time = tz.localize(datetime.datetime.utcnow()+datetime.timedelta(hours=8))
    for apl in appeal_list:
        created_date = datetime.datetime.strptime(apl['created_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
        _id = str(apl['_id'])
        calc_id = apl.get('calculation', '')
        calc = db.get_calc_in_org(calc_id, company_name) if calc_id else ''
        status = datetime.datetime.strptime(apl['created_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y") + '-Q' + str(int(datetime.datetime.strptime(apl['created_at'], "%Y-%m-%d %H:%M:%S").strftime("%m")) // 3 if int(datetime.datetime.strptime(apl['created_at'], "%Y-%m-%d %H:%M:%S").strftime("%m")) // 3 > 0 else 4)
        # policy = db.get_policy_in_org(calc['policy'], company_name)
        # calc_name = "%s:%s" % (calc['title'], policy['title'])
        # data.append([{'status': status, 'created_date':created_date, '_id':_id, 'calculation_name':calc_name}])
        data.append([{'status': status, 'created_date': created_date, '_id': _id}])
    if company_name == 'greenvalley' or company_name == 'gvtest':
        hierarchy = db.get_sim_hierarchy(user_id, company_name)
        if hierarchy.get('bu', '') == "丹酚":
            if tz.localize(datetime.datetime.strptime(vaild_time.get('startAppealTime_danfen', '1970-01-01 00:00:00'), "%Y-%m-%d %H:%M:%S"))\
                < now_time < \
                tz.localize(datetime.datetime.strptime(vaild_time.get('endAppealTime_danfen', '2999-01-01 00:00:00'), "%Y-%m-%d %H:%M:%S")):
                return jsonify(success=True, is_appealing=True, message='', data=data)
            else:
                return jsonify(success=True, is_appealing=False, message='', data=data)
        elif hierarchy.get('bu', '') == "伟素":
            if tz.localize(datetime.datetime.strptime(vaild_time.get('startAppealTime_weisu', '1970-01-01 00:00:00'), "%Y-%m-%d %H:%M:%S"))\
                < now_time < \
                tz.localize(datetime.datetime.strptime(vaild_time.get('endAppealTime_weisu', '2999-01-01 00:00:00'), "%Y-%m-%d %H:%M:%S")):
                return jsonify(success=True, is_appealing=True, message='', data=data)
            else:
                return jsonify(success=True, is_appealing=False, message='', data=data)
        else:
            return jsonify(success=False, is_appealing=False, message='无效的BU', data=data)
    else:
       return jsonify(success=True, is_appealing=True, message='', data=data) 


@app.route('/api/appeal/info/<appeal_id>')
def api_appeal_info(appeal_id):
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    apl = db.get_appeals_by_id(appeal_id, company_name)
    calc_id = apl.get('calculation', '')
    calc = db.get_calc_in_org(calc_id, company_name) if calc_id else ''
    if calc:
        policy = db.get_policy_in_org(calc['policy'], company_name)
        calc_name = "%s:%s" % (calc['title'], policy['title'])
        data = {
            "描述": apl['comment'],
            "创建时间": apl['created_at']}
        return jsonify(success=True, message='', data=data)
    else:
        data = {
            "描述": apl['comment'],
            "创建时间": apl['created_at']}
        return jsonify(success=True, message='', data=data)


@app.route('/api/appeal/new', methods=['POST'])
def api_appeal_new():
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    comment = request.form.get('comment', '')
    if comment == '':
        return jsonify(sucess=False, message='创建失败，申诉内容不能为空')
    if company_name == 'greenvalley' or company_name == 'gvtest':
        tz = pytz.timezone('Asia/Shanghai')
        now_time = datetime.datetime.now(tz)
        now_time = now_time.strftime("%Y-%m-%d %H:%M:%S")
        vaild_time = db.get_setting_by_company(company_name)
        if datetime.datetime.strptime(now_time, "%Y-%m-%d %H:%M:%S") > datetime.datetime.strptime(vaild_time['endAppealTime'], "%Y-%m-%d %H:%M:%S"):
            return jsonify(sucess=False, message='创建失败')
        new = db.create_appeal_gv(company_name, user_id, comment)
        url = 'https://forceclouds-notice.herokuapp.com/mail/send?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwcm9kdWN0IjoiQ1JNIn0.lzy8W_iSLQAyG8E3jhs8_PyQ5mssKPFGYOcLG9ifyfQ'
        sim_uinfo = db.get_sim_hierarchy(user_id, company_name)
        if sim_uinfo:
            name, mail = sim_uinfo['name'], sim_uinfo['mail']
        else:
            name, mail = user_id, 'unknow'
        mail_content_rows = ["员工%s(%s)提交了申诉</br>" % (name, user_id),
                            "邮箱： %s</br>" % mail,
                            "内容为：%s</br>" % comment]
        values = {
                    'content': '\n'.join(mail_content_rows), # 消息正文
                    'to_addr': 'lgyysfe@green-valley.com', # 收件人地址
                    'to_name': '绿谷管理员', # 收件人名
                    'from_addr': '', # 发件人地址， 可选（用于收件人回复） 默认是support@forceclouds.com
                    'from_name': '', # 发件人姓名， 可选 默认是ForceClouds
                    'subject': '您有来自%s的申诉消息'%user_id, # 主题， 可选 默认是ForceClouds Message
                }
        jdata = json.dumps(values)
        req = urllib2.Request(url,jdata)
        req.add_header('Content-Type','application/json')
        response = urllib2.urlopen(req)
    elif company_name == 'brightfuture':
        new = db.create_appeal_gv(company_name, user_id, comment)
    else:
        calc_id = request.form.get('calculation_id', '')
        calc = db.get_calc_in_org(calc_id, company_name)
        policy_name = db.get_policy_by_id(calc['policy'],company_name)
        if calc:
            new = db.create_appeal(company_name, calc_id, user_id, comment)
        else:
            return jsonify(sucess=False, message='无效的计算')
    if new:
        return jsonify(success=True, message='')
    else:
        return jsonify(sucess=False, message='创建失败')


@app.route('/api/appeal/delete', methods=['GET', 'POST'])
def delete_appeal():
    if request.method == 'POST':
        if not lib.is_im_staff(session):
            return jsonify(success=False, message=txt.BAD_AUTHORITY)
        appeal_id = request.args.get('id', '')
        owner = session.get(const.SESSION_USERNAME[0], '')
        deleted = db.delete_appeal_by_id(owner, appeal_id)
        return jsonify(success=True, message=u"删除成功！")
    else:
        appeal_id = request.args.get('id', '')
        owner = session.get(const.SESSION_USERNAME[0], '')
        deleted = db.delete_appeal_by_id(owner, appeal_id)
        return redirect('/appeal')
    return redirect('/appeal')


@app.route('/api/morpheme/new', methods=['POST'])
def create_morpheme():
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY) 
    title = request.form.get('title', '')
    level = request.form.get('level', '')
    auth = {'tag':request.form.get('tag',''),'level':request.form.get('level','')}
    tag = request.form.get('tag','')
    owner = session.get(const.SESSION_USERNAME[0], '')
    html = request.form.get('html','')
    rslt = db.create_morpheme(level,auth,title,tag,owner,html)
    return redirect('/morpheme')



# @app.route('/api/sim')
# def api_simulator_index():
#     # 验证通过SSO登录的用户的JWT
#     company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
#     if not company_name or not user_id:
#         return jsonify(success=False, message=msg)
#     return jsonify(success=True, policies=db.get_simable_policies(company_name))


# @app.route('/api/sim/<policy_id>', methods=['GET', 'POST'])
# def api_simulator_kpi(policy_id):
#     # 验证通过SSO登录的用户的JWT
#     company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
#     if not company_name or not user_id:
#         return jsonify(success=False, message=msg)
#     policy, kpis = db.get_sim_data(company_name, policy_id)
#     if not policy or not kpis:
#         return jsonify(success=False, message='无效的方案ID。')
#     if request.method == 'POST':
#         kpibase = {}
#         for kpi in kpis:
#             if kpi['source'] in ('data', 'calc', 'const'):
#                 if kpi['source'] == 'const':
#                     kpibase[kpi['name']] = kpi['value']
#                 else:
#                     if kpi['type'] == 'bool' or (kpi['source'] == 'data' and kpi['aggre_method'] == 'na'):
#                         kpibase[kpi['name']] = request.form.get('kpi_%s' % kpi['name'], 'off') == 'on'
#                     elif kpi['source'] == 'data' and kpi['aggre_method'] in ('set', 'list'):
#                         kpibase[kpi['name']] = request.form.get('kpi_%s' % kpi['name'],
#                                                                 kpi['default']).replace('；', ';').split(';')
#                     else:
#                         kpibase[kpi['name']] = request.form.get('kpi_%s' % kpi['name'], kpi['default'])
#         sim_id = db.create_simulation(policy_id,
#                                       policy['title'],
#                                       kpibase,
#                                       user_id,
#                                       company_name)
#         if not sim_id:
#             return jsonify(success=False, message='创建模拟计算失败。')
#         success, msg = executeSimulation(policy,
#                                          {const.TASK_ARG_SIM_ID: sim_id,
#                                           const.TASK_ARG_DATA_DB: company_name,
#                                           const.TASK_ARG_SIM_KPI: kpibase,
#                                           const.TASK_ARG_OWNER: user_id})
#         if success:
#             return jsonify(success=True, result=msg)
#         else:
#             return jsonify(success=False, message=msg)
#     return jsonify(success=True, kpis=kpis)


@app.route('/api/external/morpheme/list')
def api_external_list_morpheme():
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    if company_name == 'az':
        uinfo = db.get_sim_hierarchy(user_id.upper(), company_name)
        if not uinfo:
            return jsonify(success=False, message='找不到架构数据。')
        elif db.list_morphemes(session.get(const.SESSION_USERNAME[0], '')) == None:
            return jsonify(success=False, message='暂时没有可供查看的政策。')
        else:
            # print (uinfo)
            morphemes=[m for m in db.list_morphemes(cfg.AZ_OWNER)]
            data=[]
            for i in morphemes:
                if i.get('tag') == '' and i.get('level') == '':
                    data.append({'morpheme_title':str(i['title']), 'morpheme_id':str(i['_id'])})
                elif i.get('tag') == uinfo.get('tag') and i.get('level') == '':
                    data.append({'morpheme_title':str(i['title']), 'morpheme_id':str(i['_id'])})
                elif i.get('level') == uinfo.get('level') and i.get('tag') == '':
                    data.append({'morpheme_title':str(i['title']), 'morpheme_id':str(i['_id'])})
                elif i.get('level') == uinfo.get('level') and i.get('tag') == uinfo.get('tag'):
                    data.append({'morpheme_title':str(i['title']), 'morpheme_id':str(i['_id'])})
            return jsonify(success=True, data=data)
    if company_name == 'brightfuture':
        morphemes=[m for m in db.list_morphemes(cfg.BrightFuture_OWNER)]
        data=[]
        for i in morphemes:
            data.append({'morpheme_title':str(i['title']), 'morpheme_id':str(i['_id'])})
        return jsonify(success=True, data=data) 

@app.route('/api/external/morpheme/<morpheme_id>')
def api_external_show_morpheme(morpheme_id):
    company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    if not company_name or not user_id:
        return jsonify(success=False, message=msg)
    if company_name == 'az':
        owner = cfg.AZ_OWNER
    if company_name == 'brightfuture':
        owner = cfg.BrightFuture_OWNER
    morpheme = db.get_morpheme_by_id(morpheme_id, owner=owner)
    if morpheme:
        morpheme = base64.b64encode(morpheme.get('html').replace('<input type="text" data-formula="e=mc^2" data-link="https://quilljs.com" data-video="Embed URL">','').replace('</div><div class="ql-clipboard" contenteditable="true" tabindex="-1"></div><div class="ql-tooltip ql-hidden"><a class="ql-preview" target="_blank" href="about:blank"></a><a class="ql-action"></a><a class="ql-remove"></a></div>','').replace('<div class="ql-editor" data-gramm="false" contenteditable="true">','').replace('</p>','</p><br>'))
        return jsonify(data=morpheme,success=True)
    else:
        return jsonify(data=[], success=False, message=u'政策页不存在')


@app.route('/api/query/confirm', methods=['POST'])
def api_query_confirm():
    #　犯懒的共用代码。
    if request.args.get('jwt', ''):
        company_name, user_id, msg = _verify_mobile_token(request.args.get('jwt', ''))
    else:
        company_name = session.get(const.SESSION_COMPANY[0], '')
        user_id = session.get(const.SESSION_USERNAME[0], '').split('@')[0]
    if not company_name or not user_id:
        return jsonify(success=False, message='非法的登录信息！')
    calc_id = request.form.get('calc', '')
    calc = db.get_calc_in_org(calc_id, company_name)
    if not calc:
        return jsonify(success=False, data={}, message="无效的计算ID！")
    confirm_result = db.create_calc_confirm(user_id, calc_id, company_name)
    if company_name == 'greenvalley' or company_name == 'gvtest':
        with open('incentivepower/conf/greenvalley_vp.json', 'rb') as query_color_file:
            # 两层总监的绿谷部分需要等到下属都确认过自己才能确认
            vp_json = json.load(query_color_file)
            if u'自营' in policy['title']:
                vp_json = vp_json[u'丹酚自营']
            elif u'伟素' in policy['title']:
                vp_json = vp_json[u'伟素']
            elif u'丹酚' in policy['title']:
                vp_json = vp_json[u'丹酚']
            else:
                vp_json = {}
            if company_name.upper() in vp_json:
                for sub_vp in vp_json[user_id.upper()]:
                    if not db.get_calc_confirm_in_org_by_info(sub_vp, calc_id, company_name):
                        flash('下属总监仍未全部确认！')
                        return redirect('/search/calc/%s' % calc_id)
    if confirm_result:
        return jsonify(success=True, data={}, message="确认成功！")
    else:
        return jsonify(success=False, data={}, message="确认失败！请勿重复提交！")


@app.route('/api/search/confirm', methods=['POST'])
def api_search_confirm():
    if not lib.is_employee(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    company = session.get(const.SESSION_COMPANY[0], '')
    calc_id = request.form.get('id', '')
    calc = db.get_calc_in_org(calc_id, company)
    policy = db.get_policy_in_org(calc['policy'], company)
    if not calc:
        return jsonify(success=False, message=txt.CALC_NOT_FOUND)
    user_code = session.get(const.SESSION_USERNAME[0], '').split('@')[0]
    if company == 'greenvalley' or company == 'gvtest':
        with open('incentivepower/conf/greenvalley_vp.json', 'rb') as query_color_file:
            # 两层总监的绿谷部分需要等到下属都确认过自己才能确认
            vp_json = json.load(query_color_file)
            if u'自营' in policy['title']:
                vp_json = vp_json[u'丹酚自营']
            elif u'伟素' in policy['title']:
                vp_json = vp_json[u'伟素']
            elif u'丹酚' in policy['title']:
                vp_json = vp_json[u'丹酚']
            else:
                vp_json = {}
            if user_code.upper() in vp_json:
                for sub_vp in vp_json[user_code.upper()]:
                    if not db.get_calc_confirm_in_org_by_info(sub_vp, calc_id, company):
                        return jsonify(success=False, message='下属总监仍未全部确认！')
    confirm_result = db.create_calc_confirm(user_code, calc_id, company, channel='web')
    if confirm_result:
        return jsonify(success=True, message='奖金结果已经确认')
    else:
        return jsonify(success=False, message='确认失败！请不要重复提交！')

@app.route('/api/morpheme/copy/<morpheme_id>', methods=['GET', 'POST'])
def api_morpheme_quick_copy(morpheme_id):
    if not lib.is_im_staff(session):
        return jsonify(success=False, message=txt.BAD_AUTHORITY)
    morpheme = db.get_morpheme_by_id(morpheme_id)
    if not morpheme:
        return jsonify(success=False, message=txt.MORPHEME_NOT_FOUND)
    morpheme['title'] = morpheme['title'] + u'-副本'
    flash(u'政策页复制成功。', 'success')
    return jsonify(success=True, title=calc_titles)

