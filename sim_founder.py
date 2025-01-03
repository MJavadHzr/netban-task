import torch
from sql_queries import *
from sentence_transformers import SentenceTransformer


class SimFounder:
    def __init__(self, database, model_name, threshold):
        self.db = database
        self.model = SentenceTransformer(f"sentence-transformers/{model_name}")
        self.threshold = threshold
        self.groups = dict()  # ids -> group-num string

    def get_sims(self):
        # group records with cve
        not_null_cve = self.db.query(NOT_NULL_CVE_QUERY)
        self._group_cve(not_null_cve)
        
        # group records with null cve
        null_cve = self.db.query(NULL_CVE_QUERY)
        self._group_null_cve(null_cve)

        return self._group_to_dict()

    def _group_to_dict(self):
        output_dict = self.db.query(SELECT_QUERY.format(columns='*'), return_dict=True)
        for o in output_dict:
            o['tag'] = self.groups[o['id']]
        return output_dict


    def _group_cve(self, records):
        ids = [r[0] for r in records]
        groups = [r[1] for r in records]
        self.groups = dict(zip(ids, groups))

    def _group_null_cve(self, null_cve):
        null_ids = [r[0] for r in null_cve]

        all_desc = self.db.query(SELECT_QUERY.format(columns='id, title, description'))
        idx_to_ids = [r[0] for r in all_desc]
        ids_to_idx = dict(zip(idx_to_ids, range(len(idx_to_ids))))

        sims = self._calculate_sims(null_ids, all_desc, ids_to_idx)
        values, indices = torch.topk(sims, k=2)     # most similar is the record itself
        most_sim_idx = indices[:, 1]
        most_sim_val = values[:, 1]

        self._team_up(null_ids, most_sim_idx, most_sim_val, idx_to_ids)
        self._assign_remaining([id for id in null_ids if id not in self.groups.keys()])

    def _calculate_sims(self, null_ids, all_desc, ids_to_idx):
        all_desc_str = [f"Title: {r[1]}\nDescription: {r[2]}" for r in all_desc]
        encodes = self.model.encode(all_desc_str)
        sims = self.model.similarity(encodes, encodes)
        sims = sims[[ids_to_idx[id] for id in null_ids], :]
        return sims

    def _team_up(self, null_ids, most_sim_idx, most_sim_val, idx_to_ids):
        for i, v in enumerate(most_sim_val):
            if v >= self.threshold:
                src_ids = null_ids[i]
                target_ids = idx_to_ids[most_sim_idx[i]]

                if src_ids in self.groups.keys():
                    self.groups[target_ids] = self.groups[src_ids]
                elif target_ids in self.groups.keys():
                    self.groups[src_ids] = self.groups[target_ids]
                else:
                    new_group = f"group_{len(set(self.groups.values()))+1}"
                    self.groups[src_ids] = new_group
                    self.groups[target_ids] = new_group

    def _assign_remaining(self, not_assigned_null_ids):
        if len(not_assigned_null_ids) == 0:
            return
        for id in not_assigned_null_ids:
            new_group = f"group_{len(set(self.groups.values()))+1}"
            self.groups[id] = new_group
