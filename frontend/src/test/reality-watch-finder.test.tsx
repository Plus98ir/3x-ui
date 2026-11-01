import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent } from '@testing-library/react';

import RealityTargetScannerModal from '@/pages/inbounds/form/security/RealityTargetScannerModal';
import { HttpUtil, Msg } from '@/utils';
import { makeTestQueryClient, renderWithProviders } from './test-utils';

const target = (sni: string, filtered: boolean) => ({
  sni,
  ip: '203.0.113.20',
  score: 90,
  ms: 200,
  filtered,
  same24: true,
  sameAsn: true,
  cdn: '',
  dnsMatch: true,
  issuer: 'Sectigo',
  expires: '',
});

function renderScanner(picked: string[] | undefined) {
  const onClose = vi.fn();
  const onPickTarget = vi.fn();
  const view = renderWithProviders(
    <RealityTargetScannerModal
      open
      onClose={onClose}
      scanRealityCandidates={async () => []}
      onPick={() => {}}
      onPickTarget={onPickTarget}
      inboundPort={443}
      listen=""
      currentTarget=""
      picked={picked}
    />,
    { queryClient: makeTestQueryClient() },
  );
  fireEvent.click(view.getByRole('tab', { name: 'From my internet' }));
  return { ...view, onClose, onPickTarget };
}

describe('REALITY watch spares from the finder', () => {
  beforeEach(() => {
    sessionStorage.clear();
    sessionStorage.setItem(
      'realityFinder.command.443.',
      JSON.stringify({
        token: 'tok',
        expiresAt: 4102444800,
        server: '203.0.113.10',
        unix: 'u',
        windows: 'w',
      }),
    );
    vi.spyOn(HttpUtil, 'get').mockResolvedValue(
      new Msg(true, '', [
        {
          at: 1,
          network: { ip: '5.120.1.2', asn: 197207, org: 'MCI', country: 'IR' },
          warning: '',
          router: false,
          tested: 10,
          server: { ip: '203.0.113.10', asn: 1, holder: '', prefix: '' },
          port: 443,
          filterTested: true,
          targets: [target('a.example.com', false), target('b.example.com', false)],
        },
      ]),
    );
  });

  it('stays open after a pick so several spares can be added', async () => {
    const { findAllByRole, onClose, onPickTarget } = renderScanner([]);

    fireEvent.click((await findAllByRole('button', { name: 'Use' }))[0]);

    expect(onPickTarget).toHaveBeenCalledWith('a.example.com:443', ['a.example.com']);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('marks a target that is already a spare instead of offering it again', async () => {
    const { findAllByRole, getByLabelText } = renderScanner(['a.example.com:443']);

    expect(await findAllByRole('button', { name: 'Use' })).toHaveLength(1);
    expect(getByLabelText('a.example.com')).toBeTruthy();
  });

  it('closes after a pick when it sets the inbound target', async () => {
    const { findAllByRole, onClose } = renderScanner(undefined);

    fireEvent.click((await findAllByRole('button', { name: 'Use' }))[0]);

    expect(onClose).toHaveBeenCalled();
  });
});
