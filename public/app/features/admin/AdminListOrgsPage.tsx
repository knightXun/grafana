import React, { FC } from 'react';
import { getNavModel } from 'app/core/selectors/navModel';
import Page from 'app/core/components/Page/Page';
import { useSelector } from 'react-redux';
import { StoreState } from 'app/types/store';
import { LinkButton } from '@grafana/ui';
import { getBackendSrv } from '@grafana/runtime';
import { AdminOrgsTable } from './AdminOrgsTable';
import { useAsyncFn } from 'react-use';

const deleteOrg = async (orgId: number) => {
  return await getBackendSrv().delete('/api/orgs/' + orgId);
};

const getOrgs = async () => {
  return await getBackendSrv().get('/api/orgs');
};

export const AdminListOrgsPages: FC = () => {
  const navIndex = useSelector((state: StoreState) => state.navIndex);
  const navModel = getNavModel(navIndex, 'global-orgs');
  const [state, fetchOrgs] = useAsyncFn(getOrgs, []);
  console.log(state);
  fetchOrgs();

  return (
    <Page navModel={navModel}>
      <Page.Contents>
        <>
          <div className="page-action-bar">
            <div className="page-action-bar__spacer"></div>
            <LinkButton href="org/new">New org</LinkButton>
          </div>
          {state.loading && 'Ftehcing organizations'}
          {state.error}
          {state.value && (
            <AdminOrgsTable
              orgs={state.value}
              onDelete={orgId => {
                deleteOrg(orgId);
                fetchOrgs();
              }}
            />
          )}
        </>
      </Page.Contents>
    </Page>
  );
};

export default AdminListOrgsPages;
