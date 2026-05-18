from core.approvals import create_approval, approve, deny


def require_approval(command: str, risk: str):
    req = create_approval(
        project='legion-cli',
        target='',
        agent='cli',
        action='execute_command',
        command_preview=command,
        risk_level=risk,
        reason='High-risk command requires explicit approval.',
    )
    print('\n[Approval Required]')
    print(f'Risk Level: {risk}')
    print(f'Approval ID: {req["id"]}')
    print(command)

    answer = input('Approve command? (yes/no): ').strip().lower()

    if answer in ['y', 'yes']:
        approve(req['id'])
        return

    deny(req['id'])
    if answer not in ['y', 'yes']:
        raise Exception('Command rejected by user.')
