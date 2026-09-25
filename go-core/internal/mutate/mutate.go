// Package mutate ports file mutation semantics:
//
//	routes/file_routes/mutation_handlers.py (mkdir/delete/rename/copy/move/batch/unzip)
//	features/trash.py (trash move + metadata)
//	utils/helpers/file_versions.py (version backups)
//	utils/helpers/atomic_io.py (atomic writes/copies)
//	services/file_service.py (conflict policies, staging replace)
package mutate
