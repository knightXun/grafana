import React, { FC, useState } from 'react';
import { Organization } from 'app/types';
import { Button, ConfirmModal } from '@grafana/ui';

interface Props {
  orgs: Organization[];
  onDelete: (orgId: number) => void;
}

export const AdminOrgsTable: FC<Props> = ({ orgs, onDelete }) => {
  const [deleteOrg, setDeleteOrg] = useState<Organization>();
  return (
    <table className="filter-table form-inline filter-table--hover">
      <thead>
        <tr>
          <th>Id</th>
          <th>Name</th>
          <th style={{ width: '1%' }}></th>
        </tr>
      </thead>
      <tbody>
        {orgs.map(org => (
          <tr key={`${org.id}-${org.name}`}>
            <td className="link-td">
              <a href={`admin/orgs/edit/${org.id}`}>{org.id}</a>
            </td>
            <td className="link-td">
              <a href={`admin/orgs/edit/${org.id}`}>{org.name}</a>
            </td>
            <td className="text-right">
              <Button variant="destructive" size="sm" icon="times" onClick={() => setDeleteOrg(org)} />
            </td>
          </tr>
        ))}
      </tbody>
      <ConfirmModal
        isOpen={!!deleteOrg}
        title="Delete organization"
        body={`Are you sure you want to delete ${deleteOrg.name}`}
        confirmText="Delete"
        onDismiss={() => setDeleteOrg(null)}
        onConfirm={() => {
          onDelete(deleteOrg.id);
          setDeleteOrg(null);
        }}
      />
    </table>
  );
};
