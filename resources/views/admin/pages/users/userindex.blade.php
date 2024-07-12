
@extends('layouts.app')

@section('content')
<div id="order-content">
    <h1 class="centered-header">User Management Dashboard</h1>
    <div id="message"></div>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <div class="row">
                    <div class="col col-sm-9">Manage Users</div>
                    <div class="col col-sm-3">
                        <button type="button" id="import_excel" class="btn btn-info btn-sm float-end me-2">Import to Excel</button>
                        <button type="button" id="export_excel" class="btn btn-info btn-sm float-end me-2">Export to Excel</button>
                    </div>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-bordered" id="sample_data">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Profile Image</th>
                                <th>Username</th>
                                <th>First Name</th>
                                <th>Last Name</th>
                                <th>Email</th>
                                <th>Contact</th>
                                <th>Address</th>
                                <th>Active Status</th>
                                <th>Role</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal for Add/Edit -->
<div class="modal" tabindex="-1" id="action_modal">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="post" id="sample_form">
                <div class="modal-header">
                    <h5 class="modal-title" id="dynamic_modal_title"></h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" name="name" id="name" class="form-control" required disabled />
                        <span id="name_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">First Name</label>
                        <input type="text" name="first_name" id="first_name" class="form-control" required disabled />
                        <span id="first_name_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Last Name</label>
                        <input type="text" name="last_name" id="last_name" class="form-control" required disabled />
                        <span id="last_name_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input type="email" name="email" id="email" class="form-control" required disabled />
                        <span id="email_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Contact</label>
                        <input type="text" name="contact" id="contact" class="form-control" required disabled />
                        <span id="contact_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Address</label>
                        <input type="text" name="address" id="address" class="form-control" required disabled />
                        <span id="address_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label for="role" class="form-label">Role</label>
                        <select class="form-select" id="role" name="role">
                            <option value="1">Admin</option>
                            <option value="0">Customer</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Active Status</label>
                        <select class="form-select" id="active_status" name="active_status">
                            <option value="1">Active</option>
                            <option value="0">Inactive</option>
                        </select>
                        <span id="active_status_error" class="text-danger"></span>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="id" id="id" />
                    <input type="hidden" name="action" id="action" value="Add" />
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="submit" class="btn btn-primary" id="action_button" >Edit</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Import Modal -->
<div class="modal fade" id="import_modal" tabindex="-1" aria-labelledby="importModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="post" id="import_form" enctype="multipart/form-data">
                <div class="modal-header">
                    <h5 class="modal-title" id="importModalLabel">Import Users from Excel</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="file" class="form-label">Choose Excel File</label>
                        <input type="file" class="form-control" id="file" name="file" required accept=".xls,.xlsx">
                    </div>
                    <div id="import_message"></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="submit" class="btn btn-primary">Import</button>
                    <button type="button" id="clear_import_data" class="btn btn-danger">Clear</button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection

@push('scripts')
<script>
$(document).ready(function() {
    // DataTable initialization for displaying users
    var dataTable = $('#sample_data').DataTable({
        processing: true,
        serverSide: true,
        ajax: {
            url: "{{ route('api.admin.fetchUsers') }}",
            type: "GET",
            headers: {
                'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
            },
            data: function(d) {
                d.search = $('input[type="search"]').val();
            },
            dataSrc: function(json) {
                if (json.data.length === 0) {
                    $('#sample_data tbody').html('<tr><td colspan="11" class="text-center">No records available</td></tr>');
                }
                return json.data;
            }
        },
        columns: [
            { data: 'id', name: 'id' },
            { 
                data: 'profile_image', 
                name: 'profile_image',
                render: function(data, type, full, meta) {
                    if (type === 'display') {
                        return '<img src="' + (data ? data : 'default-placeholder.png') + '" alt="Profile Image" class="img-thumbnail rounded-circle" width="30" height="30">';
                    }
                    return data;
                }
            },
            
         
            { data: 'name', name: 'name', title: 'Username' },
            { data: 'fname', name: 'first_name', title: 'First Name' },
            { data: 'lname', name: 'last_name', title: 'First Name' },
            { data: 'email', name: 'email' },
            { data: 'contact', name: 'contact' },
            { data: 'address', name: 'address' },
            { 
                data: 'active_status', 
                name: 'active_status',
                render: function(data, type, full, meta) {
                    return data ? 'Active' : 'Inactive';
                }
            },
            { 
                data: 'role', 
                name: 'role',
                render: function(data, type, full, meta) {
                    return data ? 'Admin' : 'Customer';
                }
            },
            {
                data: null,
                render: function(data, type, row) {
                    return '<button class="btn btn-primary btn-sm edit" data-id="' + row.id + '">Edit</button> ' +
                           '<button class="btn btn-danger btn-sm delete" data-id="' + row.id + '">Delete</button>';
                }
            }
        ],
        searching: true,
        language: {
            emptyTable: "No data available in table",
            info: "Showing _START_ to _END_ of _TOTAL_ entries",
            infoEmpty: "Showing 0 to 0 of 0 entries",
            lengthMenu: "Show _MENU_ entries",
            loadingRecords: "Loading...",
            processing: "Processing...",
            search: "Search:",
            zeroRecords: "No matching records found"
        },
        order: [[ 0, "desc" ]]
    });

    // Handle Add/Edit modal actions
    $('#sample_form').on('submit', function(event) {
    event.preventDefault();
    var action_url = "{{ route('api.admin.storeUser') }}";

    if ($('#action').val() == 'Edit') {
        action_url = "{{ route('api.admin.saveUser') }}";
    }

    $.ajax({
        url: action_url,
        method: "POST",
        data: $(this).serialize(),
        dataType: "json",
        success: function(data) {
            if (data.errors) {
                // Display validation errors if any
                $.each(data.errors, function(key, value) {
                    $('#' + key + '_error').html(value);
                });
            }

            if (data.success) {
                // Refresh DataTable and close modal on success
                dataTable.ajax.reload(null, false);
                $('#action_modal').modal('hide');
                $('#sample_form')[0].reset();
                $('#message').html('<div class="alert alert-success">' + data.success + '</div>');
                setTimeout(function() {
                    $('#message').html('');
                }, 5000);
            }
        }
    });
});


   // Handle Edit action
// Handle Edit action
// Handle Edit action
$(document).on('click', '.edit', function() {
    var id = $(this).data('id');
    
    $('#sample_form').find('.text-danger').html('');
    
    $.ajax({
        url: "{{ route('api.admin.getEditUserData', ['id' => ':id']) }}".replace(':id', id),
        method: 'GET',
        dataType: 'json',
        success: function(data) {
            $('#name').val(data.name);
            $('#first_name').val(data.first_name);
            $('#last_name').val(data.last_name);
            $('#email').val(data.email);
            $('#contact').val(data.contact);
            $('#address').val(data.address);
            $('#role').val(data.role);
            $('#active_status').val(data.active_status);
            $('#id').val(id);
            $('#dynamic_modal_title').text('Edit User');
            $('#action_button').val('Edit');
            $('#action').val('Edit');
            $('#action_modal').modal('show');
        },
        error: function(xhr, status, error) {
            console.error('AJAX Error:', error);
            alert('An error occurred while fetching user data. Please try again.');
        }
    });
});
;



    // Handle Delete action
    $(document).on('click', '.delete', function() {
        var id = $(this).data('id');
        if (confirm("Are you sure you want to delete this user?")) {
            $.ajax({
                url: "{{ route('api.admin.deleteUser',  ['id' => ':id']) }}".replace(':id',id),
                method: 'DELETE',
                data: { id: id },
                dataType: 'json',
                success: function(data) {
                    // Refresh DataTable on success
                    dataTable.ajax.reload(null, false);
                    $('#message').html('<div class="alert alert-success">' + data.success + '</div>');
                    setTimeout(function() {
                        $('#message').html('');
                    }, 5000);
                }
            });
        }
    });

    // Handle Import action
    $('#import_excel').click(function() {
        $('#import_form')[0].reset();
        $('#import_message').html('');
        $('#import_modal').modal('show');
    });

    $('#import_form').on('submit', function(event) {
        event.preventDefault();
        var formData = new FormData(this);
        $.ajax({
            url: "{{ route('api.admin.importUsers') }}",
            method: "POST",
            data: formData,
            contentType: false,
            processData: false,
            dataType: "json",
            success: function(data) {
                if (data.errors) {
                    // Display validation errors
                    $('#import_message').html('<div class="alert alert-danger">' + data.errors + '</div>');
                }

                if (data.success) {
                    // Refresh DataTable on success
                    dataTable.ajax.reload(null, false);
                    $('#import_message').html('<div class="alert alert-success">' + data.success + '</div>');
                    setTimeout(function() {
                        $('#import_message').html('');
                        $('#import_modal').modal('hide');
                    }, 5000);
                }
            }
        });
    });

    // Clear Import modal data
    $('#clear_import_data').click(function() {
        $('#file').val('');
        $('#import_message').html('');
    });
});
</script>

@endpush