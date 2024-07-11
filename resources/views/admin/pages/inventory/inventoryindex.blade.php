@extends('layouts.app')

@section('content')
<div id="order-content">
    <h1 class="centered-header">Product Inventory Dashboard</h1>
    <div id="message"></div>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <div class="row">
                    <div class="col col-sm-9">Manage Products</div>
                    <div class="col col-sm-3">
                        <button type="button" id="export_excel" class="btn btn-info btn-sm float-end me-2">Export to Excel</button>
                        <button type="button" id="add_data" class="btn btn-success btn-sm float-end">Add</button>
                    </div>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-bordered" id="sample_data">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Product Name</th>
                                <th>Quantity</th>
                                <th>Category</th>
                                <th>Unit Price</th>
                                <th>Total Value</th>
                                <th>Supplier</th>
                                <th>Date Added</th>
                                <th>Last Updated</th>
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
                        <label class="form-label">Product Name</label>
                        <input type="text" name="product_name" id="product_name" class="form-control" />
                        <span id="product_name_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Quantity</label>
                        <input type="number" name="quantity" id="quantity" class="form-control" />
                        <span id="quantity_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Category</label>
                        <input type="text" name="category" id="category" class="form-control" />
                        <span id="category_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Unit Price</label>
                        <input type="number" name="unit_price" id="unit_price" class="form-control" />
                        <span id="unit_price_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Supplier</label>
                        <input type="text" name="supplier" id="supplier" class="form-control" />
                        <span id="supplier_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Date Added</label>
                        <input type="date" name="date_added" id="date_added" class="form-control" />
                        <span id="date_added_error" class="text-danger"></span>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Last Updated</label>
                        <input type="date" name="last_updated" id="last_updated" class="form-control" />
                        <span id="last_updated_error" class="text-danger"></span>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="id" id="id" />
                    <input type="hidden" name="action" id="action" value="Add" />
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="submit" class="btn btn-primary" id="action_button">Add</button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection

@push('scripts')
<script>
    $(document).ready(function() {
        load_data();

        function load_data() {
            var seconds = new Date() / 1000;
            $.getJSON("{{ asset('data/productdata.json') }}" + "?" + seconds, function(data) {
                console.log("Data loaded successfully:", data);

                data.sort(function(a, b) {
                    return b.id - a.id;
                });

                var data_arr = [];

                for (var count = 0; count < data.length; count++) {
                    var total_value = data[count].quantity * data[count].unit_price;
                    var sub_array = {
                        'id': data[count].id,
                        'product_name': data[count].product_name,
                        'quantity': data[count].quantity,
                        'category': data[count].category,
                        'unit_price': data[count].unit_price,
                        'total_value': total_value.toFixed(2),
                        'supplier': data[count].supplier,
                        'date_added': data[count].date_added,
                        'last_updated': data[count].last_updated,
                        'action': '<button type="button" class="btn btn-warning btn-sm edit" data-id="' + data[count].id + '">Edit</button>&nbsp;<button type="button" class="btn btn-danger btn-sm delete" data-id="' + data[count].id + '">Delete</button>'
                    };

                    data_arr.push(sub_array);
                }

                $('#sample_data').DataTable({
                    data: data_arr,
                    order: [],
                    columns: [
                        { data: "id" },
                        { data: "product_name" },
                        { data: "quantity" },
                        { data: "category" },
                        { data: "unit_price" },
                        { data: "total_value" },
                        { data: "supplier" },
                        { data: "date_added" },
                        { data: "last_updated" },
                        { data: "action" }
                    ]
                });
            }).fail(function(jqxhr, textStatus, error) {
                var err = textStatus + ", " + error;
                console.error("Request Failed: " + err);
                $('#message').html('<div class="alert alert-danger">Error loading data</div>');
            });
        }

        $('#add_data').click(function() {
            $('#dynamic_modal_title').text('Add Product');
            $('#sample_form')[0].reset();
            $('#action').val('Add');
            $('#action_button').text('Add');
            $('.text-danger').text('');
            $('#action_modal').modal('show');
        });

        $('#sample_form').on('submit', function(event) {
            event.preventDefault();

            $.ajax({
                url: "action.php",
                method: "POST",
                data: $('#sample_form').serialize(),
                dataType: "JSON",
                beforeSend: function() {
                    $('#action_button').attr('disabled', 'disabled');
                },
                success: function(data) {
                    $('#action_button').attr('disabled', false);
                    if (data.error) {
                        if (data.error.product_name_error) {
                            $('#product_name_error').text(data.error.product_name_error);
                        }
                        if (data.error.quantity_error) {
                            $('#quantity_error').text(data.error.quantity_error);
                        }
                        if (data.error.category_error) {
                            $('#category_error').text(data.error.category_error);
                        }
                        if (data.error.unit_price_error) {
                            $('#unit_price_error').text(data.error.unit_price_error);
                        }
                        if (data.error.supplier_error) {
                            $('#supplier_error').text(data.error.supplier_error);
                        }
                        if (data.error.date_added_error) {
                            $('#date_added_error').text(data.error.date_added_error);
                        }
                        if (data.error.last_updated_error) {
                            $('#last_updated_error').text(data.error.last_updated_error);
                        }
                    } else {
                        $('#message').html('<div class="alert alert-success">' + data.success + '</div>');
                        $('#action_modal').modal('hide');
                        $('#sample_data').DataTable().destroy();
                        load_data();
                        setTimeout(function() {
                            $('#message').html('');
                        }, 5000);
                    }
                }
            });
        });

        $(document).on('click', '.edit', function() {
            var id = $(this).data('id');
            $('#dynamic_modal_title').text('Edit Product');
            $('#action').val('Edit');
            $('#action_button').text('Edit');
            $('.text-danger').text('');
            $('#action_modal').modal('show');

            $.ajax({
                url: "action.php",
                method: "POST",
                data: { id: id, action: 'fetch_single' },
                dataType: "JSON",
                success: function(data) {
                    $('#product_name').val(data.product_name);
                    $('#quantity').val(data.quantity);
                    $('#category').val(data.category);
                    $('#unit_price').val(data.unit_price);
                    $('#supplier').val(data.supplier);
                    $('#date_added').val(data.date_added);
                    $('#last_updated').val(data.last_updated);
                    $('#id').val(data.id);
                }
            });
        });

        $(document).on('click', '.delete', function() {
            var id = $(this).data('id');

            if (confirm("Are you sure you want to delete this product?")) {
                $.ajax({
                    url: "action.php",
                    method: "POST",
                    data: { action: 'delete', id: id },
                    dataType: "JSON",
                    success: function(data) {
                        $('#message').html('<div class="alert alert-success">' + data.success + '</div>');
                        $('#sample_data').DataTable().destroy();
                        load_data();
                        setTimeout(function() {
                            $('#message').html('');
                        }, 5000);
                    }
                });
            }
        });

        // Export to Excel functionality
        $('#export_excel').click(function() {
            $.ajax({
                url: "export_excel.php",
                method: "GET",
                success: function(data) {
                    var blob = new Blob([data]);
                    var link = document.createElement('a');
                    link.href = window.URL.createObjectURL(blob);
                    link.download = "product_inventory_data.xlsx";
                    link.click();
                }
            });
        });
    });
</script>
@endpush
